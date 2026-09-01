// ================================================================
//  PART 1: HELPERS, AUTH & USER HANDLERS (المساعدات العامة)
// ================================================================

// ===== المساعدات =====
function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Content-Type': 'application/json'
  };
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: corsHeaders()
  });
}

function errorResponse(message, status = 400) {
  return jsonResponse({ success: false, error: message }, status);
}

function successResponse(data) {
  return jsonResponse({ success: true, data });
}

function getAuthToken(request) {
  const auth = request.headers.get('Authorization');
  if (!auth) return null;
  return auth.replace('Bearer ', '');
}

// ===== التحقق من التوكن مع استبعاد المستخدمين المحذوفين =====
async function verifyToken(token, env) {
  if (!token) return null;
  try {
    const stmt = await env.DB.prepare(
      'SELECT * FROM users WHERE token = ? AND (deleted_at IS NULL OR deleted_at = "")'
    ).bind(token);
    const result = await stmt.first();
    return result || null;
  } catch (e) {
    return null;
  }
}

function generateToken() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  const random = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return 'token_' + Date.now() + '_' + random;
}

// ===== تخزين الصور في KV =====
async function storeImage(env, fileData, key) {
  if (!env.IMAGES) return null;
  await env.IMAGES.put(key, fileData, { expirationTtl: 60 * 60 * 24 * 365 });
  return `${env.IMAGE_URL_PREFIX || 'https://bright-quizzes.brightquizzes.workers.dev/api/images'}/${key}`;
}

async function getImage(env, key) {
  if (!env.IMAGES) return null;
  return await env.IMAGES.get(key);
}
// ===== 1. تسجيل الدخول (مع توحيد is_admin) =====
async function handleUserLogin(request, env) {
  try {
    const body = await request.json();
    const { username, password } = body;
    if (!username || !password) return errorResponse('اسم المستخدم وكلمة المرور مطلوبان');

    const stmt = await env.DB.prepare(
      'SELECT * FROM users WHERE username = ? AND password = ? AND (deleted_at IS NULL OR deleted_at = "")'
    ).bind(username, password);
    const user = await stmt.first();

    if (!user) return errorResponse('اسم المستخدم أو كلمة المرور غير صحيحة', 401);

    const token = generateToken();
    await env.DB.prepare('UPDATE users SET token = ? WHERE id = ?')
      .bind(token, user.id)
      .run();

    return successResponse({
      token,
      user: {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        email: user.email,
        badge: user.badge || 'none',
        governorate: user.governorate,
        school: user.school,
        age: user.age,
        avatar: user.avatar || null,
        is_admin: user.is_admin === 1,
        created_at: user.created_at
      }
    });
  } catch (e) {
    return errorResponse(e.message);
  }
}

// ===== 2. إنشاء حساب =====
async function handleUserSignup(request, env) {
  try {
    const body = await request.json();
    const { username, full_name, email, password, age, governorate, school } = body;
    if (!username || !full_name || !email || !password) {
      return errorResponse('جميع الحقول المطلوبة يجب تعبئتها');
    }

    const check = await env.DB.prepare(
      'SELECT id FROM users WHERE (username = ? OR email = ?) AND (deleted_at IS NULL OR deleted_at = "")'
    ).bind(username, email);
    const existing = await check.first();
    if (existing) return errorResponse('اسم المستخدم أو البريد الإلكتروني مستخدم بالفعل');

    const token = generateToken();
    const stmt = await env.DB.prepare(`
      INSERT INTO users (username, full_name, email, password, age, governorate, school, badge, token, is_admin, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'none', ?, 0, datetime('now'))
    `).bind(username, full_name, email, password, age || null, governorate || null, school || null, token);

    await stmt.run();

    return successResponse({
      token,
      user: {
        username, full_name, email,
        badge: 'none',
        governorate: governorate || null,
        school: school || null,
        age: age || null,
        avatar: null,
        is_admin: false
      }
    });
  } catch (e) {
    return errorResponse(e.message);
  }
}

// ===== 3. جلب بيانات المستخدم الحالي =====
async function handleUserMe(request, env) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user) return errorResponse('توكن غير صالح', 401);

  return successResponse({
    id: user.id,
    username: user.username,
    full_name: user.full_name,
    email: user.email,
    badge: user.badge || 'none',
    governorate: user.governorate,
    school: user.school,
    age: user.age,
    avatar: user.avatar || null,
    is_admin: user.is_admin === 1,
    created_at: user.created_at
  });
}

// ===== 4. جلب بروفايل مستخدم آخر (عام) مع is_admin =====
async function handleUserProfileById(request, env) {
  const url = new URL(request.url);
  const id = url.searchParams.get('id');
  const username = url.searchParams.get('username');

  if (!id && !username) return errorResponse('معرف المستخدم أو اسم المستخدم مطلوب');

  try {
    let query = 'SELECT id, username, full_name, badge, governorate, school, age, avatar, is_admin, created_at FROM users WHERE (deleted_at IS NULL OR deleted_at = "")';
    let param;
    if (id) {
      query += ' AND id = ?';
      param = parseInt(id);
    } else {
      query += ' AND username = ?';
      param = username;
    }
    const stmt = await env.DB.prepare(query).bind(param);
    const user = await stmt.first();

    if (!user) return errorResponse('المستخدم غير موجود', 404);

    const stats = {
      total_answers: 0,
      accuracy: 0,
      categories: []
    };

    const followersStmt = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM follows WHERE following_id = ?'
    ).bind(user.id);
    const followers = await followersStmt.first();
    const followingStmt = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM follows WHERE follower_id = ?'
    ).bind(user.id);
    const following = await followingStmt.first();

    return successResponse({
      ...user,
      followers_count: followers?.count || 0,
      following_count: following?.count || 0,
      stats
    });
  } catch (e) {
    return errorResponse(e.message);
  }
}
// ===== 5. التحقق من التوكن =====
async function handleVerifyToken(request, env) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user) return errorResponse('توكن غير صالح', 401);

  return successResponse({
    valid: true,
    user: {
      id: user.id,
      username: user.username,
      full_name: user.full_name,
      email: user.email,
      badge: user.badge || 'none',
      avatar: user.avatar || null,
      is_admin: user.is_admin === 1
    }
  });
}

// ===== 6. تحديث صورة البروفايل (مع إعادة بيانات المستخدم) =====
async function handleAvatarUpload(request, env) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user) return errorResponse('توكن غير صالح', 401);

  try {
    const formData = await request.formData();
    const file = formData.get('avatar');
    if (!file) return errorResponse('الملف مطلوب');

    if (file.size > 5 * 1024 * 1024) return errorResponse('حجم الصورة يجب أن يكون أقل من 5 ميجابايت');

    const buffer = await file.arrayBuffer();
    const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    const mimeType = file.type || 'image/jpeg';
    const dataUrl = `data:${mimeType};base64,${base64}`;

    const key = `avatar_${user.id}_${Date.now()}`;
    const imageUrl = await storeImage(env, dataUrl, key);
    if (!imageUrl) return errorResponse('فشل رفع الصورة إلى التخزين');

    await env.DB.prepare('UPDATE users SET avatar = ? WHERE id = ?')
      .bind(imageUrl, user.id)
      .run();

    // إعادة بيانات المستخدم المحدثة
    const updatedUser = await env.DB.prepare(
      'SELECT id, username, full_name, email, badge, governorate, school, age, avatar, is_admin, created_at FROM users WHERE id = ?'
    ).bind(user.id).first();

    return successResponse({ user: updatedUser });
  } catch (e) {
    return errorResponse(e.message);
  }
}

// ===== 7. تحديث الملف الشخصي (مع إعادة بيانات المستخدم) =====
async function handleUserProfileUpdate(request, env) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user) return errorResponse('توكن غير صالح', 401);

  try {
    const body = await request.json();
    const { full_name, email, age, governorate, school } = body;

    await env.DB.prepare(`
      UPDATE users
      SET full_name = ?, email = ?, age = ?, governorate = ?, school = ?
      WHERE id = ?
    `).bind(
      full_name || user.full_name,
      email || user.email,
      age || user.age,
      governorate || user.governorate,
      school || user.school,
      user.id
    ).run();

    const updatedUser = await env.DB.prepare(
      'SELECT id, username, full_name, email, badge, governorate, school, age, avatar, is_admin, created_at FROM users WHERE id = ?'
    ).bind(user.id).first();

    return successResponse({ user: updatedUser });
  } catch (e) {
    return errorResponse(e.message);
  }
}

// ===== 8. حذف الحساب (Soft Delete) =====
async function handleUserDelete(request, env) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user) return errorResponse('توكن غير صالح', 401);

  try {
    await env.DB.prepare('UPDATE users SET deleted_at = datetime("now"), token = NULL WHERE id = ?')
      .bind(user.id)
      .run();

    if (user.avatar) {
      const key = user.avatar.split('/').pop();
      if (key && env.IMAGES) {
        await env.IMAGES.delete(key).catch(() => {});
      }
    }

    return successResponse({ message: 'تم حذف الحساب بنجاح' });
  } catch (e) {
    return errorResponse(e.message);
  }
}

// ===== 9. إحصائيات المستخدم (جلب حقيقي) =====
async function handleUserStats(request, env) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user) return errorResponse('توكن غير صالح', 401);

  try {
    const statsStmt = await env.DB.prepare(`
      SELECT 
        COUNT(*) as total_answers,
        AVG(percentage) as avg_accuracy,
        SUM(score) as total_score
      FROM results 
      WHERE user_id = ?
    `).bind(user.id);
    const stats = await statsStmt.first();

    const catStmt = await env.DB.prepare(`
      SELECT 
        quiz_id,
        COUNT(*) as count,
        AVG(percentage) as avg
      FROM results
      WHERE user_id = ?
      GROUP BY quiz_id
      ORDER BY count DESC
      LIMIT 5
    `).bind(user.id);
    const catResults = await catStmt.all();

    const categories = catResults.results.map(c => ({
      id: c.quiz_id?.split('_')[0] || 'general',
      name: c.quiz_id || 'عام',
      progress: Math.round(c.avg || 0),
      questions: c.count || 0
    }));

    return successResponse({
      total_answers: stats?.total_answers || 0,
      accuracy: Math.round(stats?.avg_accuracy || 0),
      total_score: stats?.total_score || 0,
      categories: categories.length > 0 ? categories : []
    });
  } catch (e) {
    return errorResponse(e.message);
  }
}
// ===== 10. نظام المتابعة =====
async function handleFollow(request, env) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user) return errorResponse('توكن غير صالح', 401);

  try {
    const body = await request.json();
    const { targetId } = body;
    if (!targetId) return errorResponse('معرف المستخدم المستهدف مطلوب');

    if (parseInt(targetId) === user.id) return errorResponse('لا يمكن متابعة النفس');

    const check = await env.DB.prepare(
      'SELECT id FROM users WHERE id = ? AND (deleted_at IS NULL OR deleted_at = "")'
    ).bind(parseInt(targetId));
    const target = await check.first();
    if (!target) return errorResponse('المستخدم غير موجود', 404);

    const existing = await env.DB.prepare(
      'SELECT id FROM follows WHERE follower_id = ? AND following_id = ?'
    ).bind(user.id, parseInt(targetId));
    const found = await existing.first();
    if (found) return errorResponse('أنت تتابع هذا المستخدم بالفعل', 400);

    await env.DB.prepare(
      'INSERT INTO follows (follower_id, following_id, created_at) VALUES (?, ?, datetime("now"))'
    ).bind(user.id, parseInt(targetId)).run();

    return successResponse({ message: 'تمت المتابعة بنجاح' });
  } catch (e) {
    return errorResponse(e.message);
  }
}

async function handleUnfollow(request, env) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user) return errorResponse('توكن غير صالح', 401);

  try {
    const body = await request.json();
    const { targetId } = body;
    if (!targetId) return errorResponse('معرف المستخدم المستهدف مطلوب');

    await env.DB.prepare(
      'DELETE FROM follows WHERE follower_id = ? AND following_id = ?'
    ).bind(user.id, parseInt(targetId)).run();

    return successResponse({ message: 'تم إلغاء المتابعة' });
  } catch (e) {
    return errorResponse(e.message);
  }
}

async function handleUserFollowing(request, env) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user) return errorResponse('توكن غير صالح', 401);

  try {
    const stmt = await env.DB.prepare(
      'SELECT following_id FROM follows WHERE follower_id = ?'
    ).bind(user.id);
    const result = await stmt.all();
    const following = result.results.map(r => r.following_id);
    return successResponse({ following });
  } catch (e) {
    return errorResponse(e.message);
  }
}

async function handleFollowersList(request, env, userId) {
  try {
    const stmt = await env.DB.prepare(`
      SELECT u.id, u.username, u.full_name, u.avatar, u.badge, u.is_admin
      FROM users u
      JOIN follows f ON u.id = f.follower_id
      WHERE f.following_id = ? AND (u.deleted_at IS NULL OR u.deleted_at = "")
    `).bind(parseInt(userId));
    const result = await stmt.all();
    return successResponse(result.results);
  } catch (e) {
    return errorResponse(e.message);
  }
}

async function handleFollowingList(request, env, userId) {
  try {
    const stmt = await env.DB.prepare(`
      SELECT u.id, u.username, u.full_name, u.avatar, u.badge, u.is_admin
      FROM users u
      JOIN follows f ON u.id = f.following_id
      WHERE f.follower_id = ? AND (u.deleted_at IS NULL OR u.deleted_at = "")
    `).bind(parseInt(userId));
    const result = await stmt.all();
    return successResponse(result.results);
  } catch (e) {
    return errorResponse(e.message);
  }
}
// ================================================================
//  PART 2: QUESTIONS HANDLERS (مع دعم Soft Delete ونقاط نهاية جديدة)
// ================================================================

// ===== الأسئلة (رفع + جلب) =====
async function handleQuestions(request, env) {
  const url = new URL(request.url);
  const quizId = url.searchParams.get('quizId');

  // POST: رفع سؤال جديد
  if (request.method === 'POST') {
    const token = getAuthToken(request);
    if (!token) return errorResponse('غير مصرح', 401);

    const user = await verifyToken(token, env);
    if (!user || user.is_admin !== 1) {
      return errorResponse('غير مصرح، تحتاج صلاحية مشرف', 403);
    }

    try {
      let body;
      let imageData = null;
      const contentType = request.headers.get('Content-Type') || '';

      if (contentType.includes('multipart/form-data')) {
        const formData = await request.formData();
        body = {
          category: formData.get('category'),
          subject: formData.get('subject'),
          model: formData.get('model'),
          question_number: parseInt(formData.get('question_number')),
          text: formData.get('text'),
          options: JSON.parse(formData.get('options') || '[]'),
          correct: parseInt(formData.get('correct')),
          explanation: formData.get('explanation'),
          model_name: formData.get('model_name')
        };
        const imageFile = formData.get('image');
        if (imageFile && imageFile.size > 0) {
          if (imageFile.size > 5 * 1024 * 1024) {
            return errorResponse('حجم الصورة يجب أن يكون أقل من 5 ميجابايت', 400);
          }
          const buffer = await imageFile.arrayBuffer();
          const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
          imageData = `data:${imageFile.type};base64,${base64}`;
        }
      } else {
        body = await request.json();
        imageData = body.image || null;
      }

      const { category, subject, model, question_number, text, options, correct, explanation, model_name } = body;

      if (!category || !subject || !model || !text || !options || correct === undefined) {
        return errorResponse('جميع الحقول المطلوبة يجب تعبئتها');
      }

      let imageUrl = null;
      if (imageData) {
        const key = `question_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
        imageUrl = await storeImage(env, imageData, key);
      }

      const stmt = await env.DB.prepare(`
        INSERT INTO questions (category, subject, model, question_number, text, options, correct, explanation, image, status, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, datetime('now'))
      `).bind(
        category, subject, model, question_number || 0,
        text, JSON.stringify(options), correct,
        explanation || null, imageUrl || null,
        user.id
      );

      await stmt.run();

      const result = await env.DB.prepare('SELECT last_insert_rowid() as id').first();
      const newId = result.id;
      const questionId = `${category}_${subject}_${model}_q${question_number}`;

      return successResponse({
        message: 'تم رفع السؤال وسينتظر الموافقة',
        id: newId,
        questionId: questionId
      });
    } catch (e) {
      return errorResponse(e.message);
    }
  }

  // GET: جلب الأسئلة
  if (request.method === 'GET') {
    // جلب الأسئلة المعلقة (pending) – للمشرفين فقط
    if (url.searchParams.get('pending') === 'true') {
      const token = getAuthToken(request);
      if (!token) return errorResponse('غير مصرح', 401);

      const user = await verifyToken(token, env);
      if (!user || user.is_admin !== 1) {
        return errorResponse('غير مصرح', 403);
      }

      try {
        const stmt = await env.DB.prepare(
          'SELECT * FROM questions WHERE status = "pending" AND (deleted_at IS NULL OR deleted_at = "") ORDER BY created_at DESC'
        );
        const questions = await stmt.all();
        const processed = questions.results.map(q => ({
          ...q,
          options: typeof q.options === 'string' ? JSON.parse(q.options) : q.options
        }));
        return successResponse({ questions: processed });
      } catch (e) {
        return errorResponse(e.message);
      }
    }

    // جلب الأسئلة حسب quizId (مع استبعاد المحذوفة)
    if (quizId) {
      try {
        const parts = quizId.split('_');
        let category = parts[0];
        if (parts[1] && ['juniors', 'youth', 'grade10', 'grade9', 'grade7', 'grade10'].includes(parts[1])) {
          category += '_' + parts[1];
        }
        const subject = parts[2] || '';
        const model = parts[3] || '';

        let query = 'SELECT * FROM questions WHERE status = "approved" AND (deleted_at IS NULL OR deleted_at = "")';
        const params = [];

        if (category) {
          query += ' AND category = ?';
          params.push(category);
        }
        if (subject) {
          query += ' AND subject = ?';
          params.push(subject);
        }
        if (model && model !== 'random') {
          query += ' AND model = ?';
          params.push(model);
        }

        if (model === 'random' || quizId.endsWith('_random')) {
          query += ' ORDER BY RANDOM() LIMIT 30';
        } else {
          query += ' ORDER BY RANDOM() LIMIT 10';
        }

        const stmt = await env.DB.prepare(query).bind(...params);
        const questions = await stmt.all();

        const processed = questions.results.map(q => ({
          ...q,
          options: typeof q.options === 'string' ? JSON.parse(q.options) : q.options
        }));

        return successResponse({ questions: processed });
      } catch (e) {
        return errorResponse(e.message);
      }
    }

    return errorResponse('معرف الاختبار مطلوب', 400);
  }

  return errorResponse('طريقة غير مدعومة', 405);
}

// ===== تحديث حالة السؤال (موافقة/رفض) =====
async function handleQuestionUpdate(request, env, id) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user || user.is_admin !== 1) {
    return errorResponse('غير مصرح', 403);
  }

  try {
    const body = await request.json();
    const { status } = body;

    if (!status || !['approved', 'rejected'].includes(status)) {
      return errorResponse('حالة غير صالحة');
    }

    await env.DB.prepare('UPDATE questions SET status = ? WHERE id = ? AND (deleted_at IS NULL OR deleted_at = "")')
      .bind(status, parseInt(id))
      .run();

    return successResponse({ message: `تم ${status === 'approved' ? 'الموافقة على' : 'رفض'} السؤال` });
  } catch (e) {
    return errorResponse(e.message);
  }
}

// ===== حذف سؤال (Soft Delete) - يدعم المعرف الرقمي والنصي =====
async function handleQuestionDelete(request, env, id) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user || user.is_admin !== 1) {
    return errorResponse('غير مصرح', 403);
  }

  try {
    let query = 'UPDATE questions SET deleted_at = datetime("now") WHERE ';
    const params = [];

    // إذا كان المعرف رقمياً
    if (/^\d+$/.test(id)) {
      query += 'id = ?';
      params.push(parseInt(id));
    } else {
      // معرف نصي مركب: category_subject_model_qNum
      const parts = id.split('_');
      let category = parts[0];
      if (parts[1] && ['juniors', 'youth', 'grade10', 'grade9', 'grade7'].includes(parts[1])) {
        category += '_' + parts[1];
        parts.splice(1, 1);
      }
      const subject = parts[1] || '';
      const model = parts[2] || '';
      const qNum = parseInt(parts[3]?.replace('q', '') || 0);

      if (!category || !subject || !model || !qNum) {
        return errorResponse('معرف غير صالح', 400);
      }

      query += 'category = ? AND subject = ? AND model = ? AND question_number = ? AND (deleted_at IS NULL OR deleted_at = "")';
      params.push(category, subject, model, qNum);
    }

    await env.DB.prepare(query).bind(...params).run();
    return successResponse({ message: 'تم حذف السؤال' });
  } catch (e) {
    return errorResponse(e.message);
  }
}
// ===== تحديث سؤال بالكامل (المحتوى) - يدعم المعرف الرقمي والنصي =====
async function handleQuestionFullUpdate(request, env, id) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user || user.is_admin !== 1) {
    return errorResponse('غير مصرح، تحتاج صلاحية مشرف', 403);
  }

  try {
    let body;
    let imageData = null;
    const contentType = request.headers.get('Content-Type') || '';

    if (contentType.includes('multipart/form-data')) {
      const formData = await request.formData();
      body = {
        category: formData.get('category'),
        subject: formData.get('subject'),
        model: formData.get('model'),
        question_number: parseInt(formData.get('question_number')),
        text: formData.get('text'),
        options: JSON.parse(formData.get('options') || '[]'),
        correct: parseInt(formData.get('correct')),
        explanation: formData.get('explanation'),
        model_name: formData.get('model_name')
      };
      const imageFile = formData.get('image');
      if (imageFile && imageFile.size > 0) {
        if (imageFile.size > 5 * 1024 * 1024) {
          return errorResponse('حجم الصورة يجب أن يكون أقل من 5 ميجابايت', 400);
        }
        const buffer = await imageFile.arrayBuffer();
        const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
        imageData = `data:${imageFile.type};base64,${base64}`;
      }
    } else {
      body = await request.json();
      imageData = body.image || null;
    }

    const { category, subject, model, question_number, text, options, correct, explanation, model_name } = body;

    if (!category || !subject || !model || !text || !options || correct === undefined) {
      return errorResponse('جميع الحقول المطلوبة يجب تعبئتها');
    }

    let imageUrl = null;
    if (imageData) {
      const key = `question_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
      imageUrl = await storeImage(env, imageData, key);
    }

    let updateQuery = `
      UPDATE questions 
      SET category = ?, subject = ?, model = ?, question_number = ?, 
          text = ?, options = ?, correct = ?, explanation = ?, model_name = ?
    `;
    const params = [category, subject, model, question_number, text, JSON.stringify(options), correct, explanation || null, model_name || null];

    if (imageUrl) {
      updateQuery += `, image = ?`;
      params.push(imageUrl);
    }

    // ✅ إصلاح: دعم المعرف النصي والرقمي
    updateQuery += ' WHERE ';
    if (/^\d+$/.test(id)) {
      updateQuery += 'id = ? AND (deleted_at IS NULL OR deleted_at = "")';
      params.push(parseInt(id));
    } else {
      const parts = id.split('_');
      let cat = parts[0];
      if (parts[1] && ['juniors', 'youth', 'grade10', 'grade9', 'grade7'].includes(parts[1])) {
        cat += '_' + parts[1];
        parts.splice(1, 1);
      }
      const subj = parts[1] || '';
      const mdl = parts[2] || '';
      const qNum = parseInt(parts[3]?.replace('q', '') || 0);

      if (!cat || !subj || !mdl || !qNum) {
        return errorResponse('معرف غير صالح', 400);
      }

      updateQuery += 'category = ? AND subject = ? AND model = ? AND question_number = ? AND (deleted_at IS NULL OR deleted_at = "")';
      params.push(cat, subj, mdl, qNum);
    }

    await env.DB.prepare(updateQuery).bind(...params).run();

    // جلب السؤال المحدث
    let fetchQuery = 'SELECT * FROM questions WHERE ';
    const fetchParams = [];
    if (/^\d+$/.test(id)) {
      fetchQuery += 'id = ?';
      fetchParams.push(parseInt(id));
    } else {
      const parts = id.split('_');
      let cat = parts[0];
      if (parts[1] && ['juniors', 'youth', 'grade10', 'grade9', 'grade7'].includes(parts[1])) {
        cat += '_' + parts[1];
        parts.splice(1, 1);
      }
      const subj = parts[1] || '';
      const mdl = parts[2] || '';
      const qNum = parseInt(parts[3]?.replace('q', '') || 0);
      fetchQuery += 'category = ? AND subject = ? AND model = ? AND question_number = ?';
      fetchParams.push(cat, subj, mdl, qNum);
    }

    const updated = await env.DB.prepare(fetchQuery).bind(...fetchParams).first();
    if (updated && updated.options) {
      updated.options = typeof updated.options === 'string' ? JSON.parse(updated.options) : updated.options;
    }

    return successResponse({ message: 'تم تحديث السؤال', question: updated });
  } catch (e) {
    return errorResponse(e.message);
  }
}
// ===== جلب سؤال مفرد بواسطة المعرف النصي – نقطة نهاية جديدة =====
async function handleGetSingleQuestion(request, env, fullId) {
  try {
    const parts = fullId.split('_');
    let category = parts[0];
    if (parts[1] && ['juniors', 'youth', 'grade10', 'grade9', 'grade7'].includes(parts[1])) {
      category += '_' + parts[1];
      parts.splice(1, 1);
    }
    const subject = parts[1] || '';
    const model = parts[2] || '';
    const qNum = parseInt(parts[3]?.replace('q', '') || 0);

    if (!category || !subject || !model || !qNum) {
      return errorResponse('معرف غير صالح', 400);
    }

    const stmt = await env.DB.prepare(`
      SELECT * FROM questions 
      WHERE category = ? AND subject = ? AND model = ? AND question_number = ?
      AND (deleted_at IS NULL OR deleted_at = "")
    `).bind(category, subject, model, qNum);
    const question = await stmt.first();
    if (!question) return errorResponse('السؤال غير موجود', 404);

    if (question.options) {
      question.options = typeof question.options === 'string' ? JSON.parse(question.options) : question.options;
    }
    return successResponse(question);
  } catch (e) {
    return errorResponse(e.message);
  }
}
// ================================================================
//  PART 3: POSTS, RESULTS, LEADERBOARD, SEARCH (مع Soft Delete)
// ================================================================

// ===== المنشورات =====
async function handlePosts(request, env) {
  if (request.method === 'POST') {
    const token = getAuthToken(request);
    if (!token) return errorResponse('غير مصرح', 401);

    const user = await verifyToken(token, env);
    if (!user) return errorResponse('توكن غير صالح', 401);

    try {
      let title, content, category, imageData = null;
      const contentType = request.headers.get('Content-Type') || '';

      if (contentType.includes('multipart/form-data')) {
        const formData = await request.formData();
        title = formData.get('title');
        content = formData.get('content');
        category = formData.get('category') || 'general';
        const imageFile = formData.get('image');
        if (imageFile && imageFile.size > 0) {
          if (imageFile.size > 5 * 1024 * 1024) {
            return errorResponse('حجم الصورة يجب أن يكون أقل من 5 ميجابايت', 400);
          }
          const buffer = await imageFile.arrayBuffer();
          const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
          imageData = `data:${imageFile.type};base64,${base64}`;
        }
      } else {
        const body = await request.json();
        title = body.title;
        content = body.content;
        category = body.category || 'general';
        imageData = body.image || null;
      }

      if (!title || !content) {
        return errorResponse('العنوان والمحتوى مطلوبان');
      }

      let imageUrl = null;
      if (imageData) {
        const key = `post_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
        imageUrl = await storeImage(env, imageData, key);
      }

      const stmt = await env.DB.prepare(`
        INSERT INTO posts (user_id, title, content, category, image, created_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
      `).bind(user.id, title, content, category, imageUrl);

      await stmt.run();
      return successResponse({ message: 'تم نشر المنشور بنجاح' });
    } catch (e) {
      return errorResponse(e.message);
    }
  }

  // GET: جلب المنشورات مع بيانات المستخدم (استبعاد المحذوفين)
  if (request.method === 'GET') {
    try {
      const stmt = await env.DB.prepare(`
        SELECT p.*, u.id as user_id, u.full_name, u.username, u.avatar, u.badge, u.is_admin
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE (u.deleted_at IS NULL OR u.deleted_at = "")
        ORDER BY p.created_at DESC
      `);
      const posts = await stmt.all();
      return successResponse({ posts: posts.results });
    } catch (e) {
      return errorResponse(e.message);
    }
  }

  return errorResponse('طريقة غير مدعومة', 405);
}

// ===== النتائج =====
async function handleResults(request, env) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user) return errorResponse('توكن غير صالح', 401);

  if (request.method === 'POST') {
    try {
      const body = await request.json();
      const { quiz_id, score, total, percentage, answers, time_spent } = body;

      const stmt = await env.DB.prepare(`
        INSERT INTO results (user_id, quiz_id, score, total, percentage, answers, time_spent, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `).bind(user.id, quiz_id, score, total, percentage, JSON.stringify(answers), time_spent || null);

      await stmt.run();
      return successResponse({ message: 'تم حفظ النتيجة' });
    } catch (e) {
      return errorResponse(e.message);
    }
  }

  // GET: جلب نتائج المستخدم
  try {
    const stmt = await env.DB.prepare('SELECT * FROM results WHERE user_id = ? ORDER BY created_at DESC')
      .bind(user.id);
    const results = await stmt.all();
    return successResponse({ results: results.results });
  } catch (e) {
    return errorResponse(e.message);
  }
}

// ===== لوحة المتصدرين (مع is_admin الموحد) =====
async function handleLeaderboard(request, env) {
  const url = new URL(request.url);
  const category = url.searchParams.get('category');

  try {
    let query = `
      SELECT u.id, u.username, u.full_name, u.badge, u.avatar,
             COUNT(r.id) as total_quizzes,
             AVG(r.percentage) as avg_score,
             SUM(r.score) as total_points,
             u.is_admin
      FROM users u
      LEFT JOIN results r ON u.id = r.user_id
      WHERE (u.deleted_at IS NULL OR u.deleted_at = "")
    `;
    const params = [];

    if (category && category !== 'all') {
      query += ` AND r.quiz_id LIKE ?`;
      params.push(`${category}%`);
    }

    query += ` GROUP BY u.id ORDER BY avg_score DESC LIMIT 100`;

    const stmt = await env.DB.prepare(query).bind(...params);
    const data = await stmt.all();

    const leaderboard = data.results.map(u => ({
      id: u.id,
      username: u.username,
      full_name: u.full_name,
      badge: u.badge || 'none',
      avatar: u.avatar || null,
      is_admin: u.is_admin === 1,
      score: Math.round(u.total_points || 0),
      accuracy: Math.round(u.avg_score || 0)
    }));

    return successResponse({ leaderboard });
  } catch (e) {
    return errorResponse(e.message);
  }
}

// ===== البحث (مع استبعاد المحذوفين) =====
async function handleSearch(request, env) {
  const url = new URL(request.url);
  const query = url.searchParams.get('q');

  if (!query || query.trim().length < 2) {
    return successResponse({ questions: [], posts: [], users: [] });
  }

  const searchTerm = `%${query.trim()}%`;

  try {
    // أسئلة
    const qStmt = await env.DB.prepare(`
      SELECT id, text as question_text, category, subject, model, options
      FROM questions
      WHERE status = 'approved' AND text LIKE ? AND (deleted_at IS NULL OR deleted_at = "")
      LIMIT 10
    `).bind(searchTerm);
    const questions = await qStmt.all();

    // منشورات
    const pStmt = await env.DB.prepare(`
      SELECT p.id, p.title, p.content, p.category, u.full_name, u.username, u.avatar
      FROM posts p
      JOIN users u ON p.user_id = u.id
      WHERE (p.title LIKE ? OR p.content LIKE ?) AND (u.deleted_at IS NULL OR u.deleted_at = "")
      LIMIT 10
    `).bind(searchTerm, searchTerm);
    const posts = await pStmt.all();

    // مستخدمون (مع is_admin)
    const uStmt = await env.DB.prepare(`
      SELECT id, username, full_name, badge, avatar, is_admin
      FROM users
      WHERE (username LIKE ? OR full_name LIKE ?) AND (deleted_at IS NULL OR deleted_at = "")
      LIMIT 10
    `).bind(searchTerm, searchTerm);
    const users = await uStmt.all();

    return successResponse({
      questions: questions.results,
      posts: posts.results,
      users: users.results
    });
  } catch (e) {
    return errorResponse(e.message);
  }
}
// ================================================================
//  PART 4: METADATA & MAIN ROUTER (مع نقاط النهاية الجديدة)
// ================================================================

// ===== البيانات الوصفية (Metadata) =====
async function handleMetadata(request, env) {
  const url = new URL(request.url);
  const category = url.searchParams.get('category');
  const subject = url.searchParams.get('subject');

  try {
    let query = 'SELECT * FROM metadata';
    const params = [];
    const conditions = [];

    if (category) {
      conditions.push('category = ?');
      params.push(category);
    }
    if (subject) {
      conditions.push('subject = ?');
      params.push(subject);
    }

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    query += ' ORDER BY sort_order ASC, model ASC';

    const stmt = await env.DB.prepare(query).bind(...params);
    const result = await stmt.all();

    const data = {};
    result.results.forEach(row => {
      if (!data[row.subject]) {
        data[row.subject] = [];
      }
      data[row.subject].push({
        model: row.model,
        display_name: row.display_name,
        icon: row.icon_class || 'fas fa-file-alt'
      });
    });

    const subjects = Object.keys(data).map(key => ({
      id: key,
      models: data[key]
    }));

    return successResponse({ subjects, metadata: result.results });
  } catch (e) {
    return errorResponse(e.message);
  }
}

// ===== إدارة النماذج (Metadata) مع is_admin =====
async function handleMetadataManagement(request, env) {
  const url = new URL(request.url);
  const method = request.method;

  if (method === 'POST') {
    const token = getAuthToken(request);
    if (!token) return errorResponse('غير مصرح', 401);

    const user = await verifyToken(token, env);
    if (!user || user.is_admin !== 1) {
      return errorResponse('غير مصرح، تحتاج صلاحية مشرف', 403);
    }

    try {
      const body = await request.json();
      const { category, subject, model, display_name, icon_class } = body;

      if (!category || !subject || !model || !display_name) {
        return errorResponse('جميع الحقول المطلوبة يجب تعبئتها');
      }

      const check = await env.DB.prepare(
        'SELECT id FROM metadata WHERE category = ? AND subject = ? AND model = ?'
      ).bind(category, subject, model);
      const existing = await check.first();

      if (existing) {
        return errorResponse('هذا النموذج موجود بالفعل لهذا القسم والمادة');
      }

      const stmt = await env.DB.prepare(`
        INSERT INTO metadata (category, subject, model, display_name, icon_class, sort_order)
        VALUES (?, ?, ?, ?, ?, (SELECT COALESCE(MAX(sort_order), 0) + 1 FROM metadata WHERE category = ? AND subject = ?))
      `).bind(category, subject, model, display_name, icon_class || null, category, subject);

      await stmt.run();

      return successResponse({
        message: 'تم إضافة النموذج بنجاح',
        model: { category, subject, model, display_name, icon_class }
      });
    } catch (e) {
      return errorResponse(e.message);
    }
  }

  if (method === 'DELETE') {
    const token = getAuthToken(request);
    if (!token) return errorResponse('غير مصرح', 401);

    const user = await verifyToken(token, env);
    if (!user || user.is_admin !== 1) {
      return errorResponse('غير مصرح، تحتاج صلاحية مشرف', 403);
    }

    try {
      const id = url.searchParams.get('id');
      if (!id) return errorResponse('معرف النموذج مطلوب');

      await env.DB.prepare('DELETE FROM metadata WHERE id = ?').bind(parseInt(id)).run();
      return successResponse({ message: 'تم حذف النموذج بنجاح' });
    } catch (e) {
      return errorResponse(e.message);
    }
  }

  return errorResponse('طريقة غير مدعومة', 405);
}
// ================================================================
//  MAIN ROUTER & EXPORT (مع جميع المسارات المعدلة والجديدة)
// ================================================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders()
      });
    }

    try {
      // ===== المستخدمون =====
      if (path === '/api/users/login' && method === 'POST') {
        return await handleUserLogin(request, env);
      }
      if (path === '/api/users/signup' && method === 'POST') {
        return await handleUserSignup(request, env);
      }
      if (path === '/api/users/me' && method === 'GET') {
        return await handleUserMe(request, env);
      }
      if (path === '/api/users/profile' && method === 'GET') {
        return await handleUserProfileById(request, env);
      }
      if (path === '/api/users/profile' && method === 'PUT') {
        return await handleUserProfileUpdate(request, env);
      }
      if (path === '/api/users/avatar' && method === 'POST') {
        return await handleAvatarUpload(request, env);
      }
      if (path === '/api/users/verify' && method === 'GET') {
        return await handleVerifyToken(request, env);
      }
      if (path === '/api/users/delete' && method === 'DELETE') {
        return await handleUserDelete(request, env);
      }
      if (path === '/api/users/stats' && method === 'GET') {
        return await handleUserStats(request, env);
      }
      // تسجيل الخروج (جديد)
      if (path === '/api/users/logout' && method === 'POST') {
        const token = getAuthToken(request);
        if (!token) return errorResponse('غير مصرح', 401);
        const user = await verifyToken(token, env);
        if (!user) return errorResponse('توكن غير صالح', 401);
        await env.DB.prepare('UPDATE users SET token = NULL WHERE id = ?').bind(user.id).run();
        return successResponse({ message: 'تم تسجيل الخروج بنجاح' });
      }
      // المتابعة
      if (path === '/api/users/follow' && method === 'POST') {
        return await handleFollow(request, env);
      }
      if (path === '/api/users/unfollow' && method === 'DELETE') {
        return await handleUnfollow(request, env);
      }
      if (path === '/api/users/me/following' && method === 'GET') {
        return await handleUserFollowing(request, env);
      }
      if (path.match(/^\/api\/users\/(\d+)\/followers$/) && method === 'GET') {
        const match = path.match(/^\/api\/users\/(\d+)\/followers$/);
        return await handleFollowersList(request, env, match[1]);
      }
      if (path.match(/^\/api\/users\/(\d+)\/following$/) && method === 'GET') {
        const match = path.match(/^\/api\/users\/(\d+)\/following$/);
        return await handleFollowingList(request, env, match[1]);
      }

      // ===== الأسئلة (مع نقاط نهاية جديدة) =====
      if (path === '/api/questions' && method === 'GET') {
        // إذا كان هناك معامل pending، نمرره إلى handleQuestions
        if (url.searchParams.get('pending') === 'true') {
          return await handleQuestions(request, env);
        }
        // وإلا نمرر أيضاً إلى handleQuestions للتعامل مع quizId
        return await handleQuestions(request, env);
      }
      if (path === '/api/questions' && method === 'POST') {
        return await handleQuestions(request, env);
      }
      if (path === '/api/questions/upload' && method === 'POST') {
        return await handleQuestions(request, env);
      }

      // جلب سؤال مفرد بواسطة المعرف النصي (جديد)
      if (path.startsWith('/api/questions/') && method === 'GET') {
        const id = path.replace('/api/questions/', '');
        if (id && !/^\d+$/.test(id)) { // إذا لم يكن رقماً
          return await handleGetSingleQuestion(request, env, id);
        }
        // إذا كان رقمياً، نمرره للمعالجة العادية (اختياري)
      }

      // تحديث حالة السؤال (موافقة/رفض) – يبقى كما هو
      if (path.match(/^\/api\/questions\/(\d+)$/) && method === 'PUT') {
        const id = path.split('/').pop();
        return await handleQuestionUpdate(request, env, id);
      }

      // تحديث السؤال بالكامل (جديد) – يدعم المعرف النصي والرقمي
      if (path.match(/^\/api\/questions\/(.+)$/) && method === 'PUT') {
        const id = path.split('/').pop();
        return await handleQuestionFullUpdate(request, env, id);
      }

      // حذف سؤال (يدعم المعرف النصي والرقمي مع Soft Delete)
      if (path.match(/^\/api\/questions\/(.+)$/) && method === 'DELETE') {
        const id = path.split('/').pop();
        if (/^\d+$/.test(id)) {
          return await handleQuestionDelete(request, env, id);
        } else {
          // المعرف النصي: نبحث عن السؤال ونحذفه
          // يمكن تنفيذ بحث مشابه لـ handleGetSingleQuestion ثم حذف النتيجة
          // لكن للتبسيط، سنمرر المعرف النصي كما هو، وسيتولى handleQuestionDelete تحليله
          return await handleQuestionDelete(request, env, id);
        }
      }

      // ===== المنشورات =====
      if (path === '/api/posts') {
        return await handlePosts(request, env);
      }

      // ===== النتائج =====
      if (path === '/api/results') {
        return await handleResults(request, env);
      }

      // ===== لوحة المتصدرين =====
      if (path === '/api/leaderboard') {
        return await handleLeaderboard(request, env);
      }

      // ===== البحث =====
      if (path === '/api/search') {
        return await handleSearch(request, env);
      }

      // ===== البيانات الوصفية =====
      if (path === '/api/metadata' && method === 'GET') {
        return await handleMetadata(request, env);
      }
      if (path === '/api/metadata/manage') {
        return await handleMetadataManagement(request, env);
      }

      // ===== جلب الصور من KV =====
      if (path.startsWith('/api/images/')) {
        const key = path.replace('/api/images/', '');
        if (!env.IMAGES) {
          return errorResponse('تخزين الصور غير متوفر', 503);
        }
        const imageData = await getImage(env, key);
        if (!imageData) {
          return errorResponse('الصورة غير موجودة', 404);
        }
        let contentType = 'image/jpeg';
        if (imageData.startsWith('data:')) {
          const match = imageData.match(/^data:([^;]+);base64,/);
          if (match) contentType = match[1];
        }
        const base64Data = imageData.split(',')[1] || imageData;
        const binary = atob(base64Data);
        const array = Uint8Array.from(binary, c => c.charCodeAt(0));
        return new Response(array.buffer, {
          headers: {
            'Content-Type': contentType,
            'Cache-Control': 'public, max-age=31536000',
            ...corsHeaders()
          }
        });
      }

      // ===== الصفحة الرئيسية =====
      if (path === '/' || path === '') {
        return new Response('Bright Quizzes API is running!', {
          headers: corsHeaders()
        });
      }

      return errorResponse('المسار غير موجود', 404);
    } catch (e) {
      console.error('Worker error:', e);
      return errorResponse('خطأ داخلي في الخادم', 500);
    }
  }
};
