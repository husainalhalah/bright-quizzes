/**
 * ================================================================
 *  Bright Quizzes API - Cloudflare Worker (Full Metrics Engine)
 *  الإصدار المتكامل: تخزين وجلب شامل لكافة إحصائيات الأسئلة والاختبارات
 * ================================================================
 */

// ================================================================
//  PART 1: المساعدات العامة، الأمان والتوثيق
// ================================================================

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, Accept',
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

function successResponse(data, status = 200) {
  return jsonResponse({ success: true, data }, status);
}

function getAuthToken(request) {
  const auth = request.headers.get('Authorization');
  if (!auth) return null;
  return auth.replace(/^Bearer\s+/i, '').trim();
}

function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  const chunkSize = 8192;
  for (let i = 0; i < len; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + chunkSize, len)));
  }
  return btoa(binary);
}

// تشفير كلمات المرور (PBKDF2)
async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return bytesToHex(new Uint8Array(bits));
}

function generateSalt() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function isValidEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(String(email).toLowerCase());
}

async function checkRateLimit(env, key, limit = 6, windowSeconds = 300) {
  if (!env.RATE_LIMIT) return true;
  const current = await env.RATE_LIMIT.get(key);
  const count = current ? parseInt(current, 10) : 0;
  if (count >= limit) return false;
  await env.RATE_LIMIT.put(key, String(count + 1), { expirationTtl: windowSeconds });
  return true;
}

function generateToken() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  const random = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return 'token_' + Date.now() + '_' + random;
}

async function storeImage(env, fileData, key, origin) {
  if (env.IMAGES) {
    await env.IMAGES.put(key, fileData, { expirationTtl: 60 * 60 * 24 * 365 });
    const prefix = env.IMAGE_URL_PREFIX || `${origin}/api/images`;
    return `${prefix}/${key}`;
  }
  return fileData;
}

async function getImage(env, key) {
  if (!env.IMAGES) return null;
  return await env.IMAGES.get(key);
}

async function verifyToken(token, env) {
  if (!token) return null;
  try {
    const stmt = await env.DB.prepare(
      `SELECT id, username, full_name, email, bio, badge, governorate, school, age, avatar, is_admin, score, created_at, deleted_at
       FROM users 
       WHERE token = ? 
       AND (deleted_at IS NULL OR deleted_at = "")
       AND (token_expires_at IS NULL OR token_expires_at > datetime('now'))`
    ).bind(token);
    return await stmt.first();
  } catch (e) {
    return null;
  }
}

// ================================================================
//  PART 2: إدارة المستخدمين، الجلسات والمتابعة
// ================================================================

async function handleUserLogin(request, env) {
  try {
    const body = await request.json();
    const { username, password } = body;
    if (!username || !password) return errorResponse('اسم المستخدم وكلمة المرور مطلوبان');

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const rlKey = `login:${ip}:${username}`;
    const allowed = await checkRateLimit(env, rlKey, 6, 300);
    if (!allowed) return errorResponse('محاولات كثيرة جداً، حاول مرة أخرى بعد قليل', 429);

    const stmt = await env.DB.prepare(
      'SELECT * FROM users WHERE (username = ? OR email = ?) AND (deleted_at IS NULL OR deleted_at = "")'
    ).bind(username, username);
    const user = await stmt.first();

    if (!user) return errorResponse('اسم المستخدم أو كلمة المرور غير صحيحة', 401);

    let valid = false;
    if (user.password_hash && user.password_salt) {
      const computed = await hashPassword(password, user.password_salt);
      valid = safeEqual(computed, user.password_hash);
    } else if (user.password) {
      valid = safeEqual(password, user.password);
      if (valid) {
        const salt = generateSalt();
        const hash = await hashPassword(password, salt);
        await env.DB.prepare(
          'UPDATE users SET password_hash = ?, password_salt = ?, password = NULL WHERE id = ?'
        ).bind(hash, salt, user.id).run();
      }
    }

    if (!valid) return errorResponse('اسم المستخدم أو كلمة المرور غير صحيحة', 401);

    const token = generateToken();
    await env.DB.prepare(
      "UPDATE users SET token = ?, token_expires_at = datetime('now', '+30 days') WHERE id = ?"
    ).bind(token, user.id).run();

    if (env.RATE_LIMIT) {
      await env.RATE_LIMIT.delete(rlKey).catch(() => {});
    }

    return successResponse({
      token,
      refreshToken: token,
      user: {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        email: user.email,
        bio: user.bio || null,
        badge: user.badge || 'none',
        governorate: user.governorate,
        school: user.school,
        age: user.age,
        avatar: user.avatar || null,
        score: user.score || 0,
        is_admin: user.is_admin === 1 || user.is_admin === true || user.is_admin === '1',
        created_at: user.created_at
      }
    });
  } catch (e) {
    return errorResponse(e.message);
  }
}

async function handleUserSignup(request, env) {
  try {
    const body = await request.json();
    const { username, full_name, email, password, age, governorate, school } = body;

    if (!username || !full_name || !email || !password) {
      return errorResponse('جميع الحقول المطلوبة يجب تعبئتها');
    }

    if (!isValidEmail(email)) {
      return errorResponse('البريد الإلكتروني غير صحيح');
    }

    const check = await env.DB.prepare(
      'SELECT id FROM users WHERE (username = ? OR email = ?) AND (deleted_at IS NULL OR deleted_at = "")'
    ).bind(username, email);
    const existing = await check.first();
    if (existing) return errorResponse('اسم المستخدم أو البريد الإلكتروني مستخدم بالفعل');

    const salt = generateSalt();
    const passwordHash = await hashPassword(password, salt);
    const token = generateToken();

    await env.DB.prepare(`
      INSERT INTO users (username, full_name, email, password_hash, password_salt, age, governorate, school, badge, token, is_admin, score, created_at, token_expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'none', ?, 0, 0, datetime('now'), datetime('now', '+30 days'))
    `).bind(
      username, full_name, email, passwordHash, salt,
      age || null, governorate || null, school || null, token
    ).run();

    const lastRow = await env.DB.prepare('SELECT last_insert_rowid() as id').first();

    return successResponse({
      token,
      refreshToken: token,
      user: {
        id: lastRow ? lastRow.id : null,
        username,
        full_name,
        email,
        bio: null,
        badge: 'none',
        governorate: governorate || null,
        school: school || null,
        age: age || null,
        avatar: null,
        score: 0,
        is_admin: false,
        created_at: new Date().toISOString()
      }
    });
  } catch (e) {
    return errorResponse(e.message);
  }
}

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
    bio: user.bio || null,
    badge: user.badge || 'none',
    governorate: user.governorate,
    school: user.school,
    age: user.age,
    avatar: user.avatar || null,
    score: user.score || 0,
    is_admin: user.is_admin === 1 || user.is_admin === true || user.is_admin === '1',
    created_at: user.created_at
  });
}

// عرض ملف المستخدم الشخصي مع كامل إحصائياته الدقيقة من قاعدة البيانات
async function handleUserProfileById(request, env) {
  const url = new URL(request.url);
  const id = url.searchParams.get('id');
  const username = url.searchParams.get('username');

  if (!id && !username) return errorResponse('معرف المستخدم أو اسم المستخدم مطلوب');

  try {
    let query = 'SELECT id, username, full_name, bio, badge, governorate, school, age, avatar, score, is_admin, created_at FROM users WHERE (deleted_at IS NULL OR deleted_at = "")';
    let param = id ? parseInt(id, 10) : username;
    query += id ? ' AND id = ?' : ' AND username = ?';

    const stmt = await env.DB.prepare(query).bind(param);
    const user = await stmt.first();
    if (!user) return errorResponse('المستخدم غير موجود', 404);

    // حساب كافة إحصائيات هذا المستخدم من جدول results
    const statsStmt = await env.DB.prepare(`
      SELECT 
        COUNT(*) as total_quizzes,
        COALESCE(SUM(total), 0) as total_questions,
        COALESCE(SUM(score), 0) as total_correct,
        COALESCE(AVG(percentage), 0) as avg_accuracy,
        COALESCE(SUM(score * 10), 0) as total_score,
        COALESCE(SUM(time_spent), 0) as total_duration
      FROM results WHERE user_id = ?
    `).bind(user.id);
    const stats = await statsStmt.first();

    const followersStmt = await env.DB.prepare('SELECT COUNT(*) as count FROM follows WHERE following_id = ?').bind(user.id);
    const followers = await followersStmt.first();

    const followingStmt = await env.DB.prepare('SELECT COUNT(*) as count FROM follows WHERE follower_id = ?').bind(user.id);
    const following = await followingStmt.first();

    let isFollowing = false;
    let followsMe = false;
    const token = getAuthToken(request);
    if (token) {
      const viewer = await verifyToken(token, env);
      if (viewer && viewer.id !== user.id) {
        const followCheck = await env.DB.prepare('SELECT 1 FROM follows WHERE follower_id = ? AND following_id = ?').bind(viewer.id, user.id).first();
        isFollowing = !!followCheck;

        const followsMeCheck = await env.DB.prepare('SELECT 1 FROM follows WHERE follower_id = ? AND following_id = ?').bind(user.id, viewer.id).first();
        followsMe = !!followsMeCheck;
      }
    }

    return successResponse({
      ...user,
      is_admin: user.is_admin === 1 || user.is_admin === true || user.is_admin === '1',
      followers_count: followers?.count || 0,
      following_count: following?.count || 0,
      is_following: isFollowing,
      follows_me: followsMe,
      stats: {
        total_quizzes: stats?.total_quizzes || 0,
        total_questions: stats?.total_questions || 0,
        correct_answers: stats?.total_correct || 0,
        accuracy: Math.round(stats?.avg_accuracy || 0),
        total_score: stats?.total_score || 0,
        total_duration: stats?.total_duration || 0,
        total_answers: stats?.total_questions || 0 // للتوافق العكسي مع الواجهات
      }
    });
  } catch (e) {
    return errorResponse(e.message);
  }
}

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
      bio: user.bio || null,
      badge: user.badge || 'none',
      avatar: user.avatar || null,
      score: user.score || 0,
      is_admin: user.is_admin === 1 || user.is_admin === true || user.is_admin === '1'
    }
  });
}

async function handleRefreshToken(request, env) {
  let token = getAuthToken(request);

  if (!token && request.method === 'POST') {
    try {
      const body = await request.clone().json();
      token = body.refreshToken || body.token || null;
    } catch (e) {}
  }

  if (!token) return errorResponse('غير مصرح', 401);

  const stmt = await env.DB.prepare(
    'SELECT * FROM users WHERE token = ? AND (deleted_at IS NULL OR deleted_at = "")'
  ).bind(token);
  const user = await stmt.first();

  if (!user) return errorResponse('انتهت صلاحية الجلسة، يرجى تسجيل الدخول مجدداً', 401);

  try {
    const newToken = generateToken();
    await env.DB.prepare(
      "UPDATE users SET token = ?, token_expires_at = datetime('now', '+30 days') WHERE id = ?"
    ).bind(newToken, user.id).run();

    return successResponse({
      token: newToken,
      refreshToken: newToken,
      user: {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        email: user.email,
        bio: user.bio || null,
        badge: user.badge || 'none',
        governorate: user.governorate,
        school: user.school,
        age: user.age,
        avatar: user.avatar || null,
        score: user.score || 0,
        is_admin: user.is_admin === 1 || user.is_admin === true || user.is_admin === '1',
        created_at: user.created_at
      }
    });
  } catch (e) {
    return errorResponse(e.message);
  }
      }
async function handleAvatarUpload(request, env) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user) return errorResponse('توكن غير صالح', 401);

  try {
    const formData = await request.formData();
    const file = formData.get('avatar');
    if (!file) return errorResponse('ملف الصورة مطلوب');
    if (file.size > 5 * 1024 * 1024) return errorResponse('حجم الصورة يجب أن يكون أقل من 5 ميجابايت');

    const buffer = await file.arrayBuffer();
    const base64 = arrayBufferToBase64(buffer);
    const mimeType = file.type || 'image/jpeg';
    const dataUrl = `data:${mimeType};base64,${base64}`;

    const url = new URL(request.url);
    const key = `avatar_${user.id}_${Date.now()}`;
    const imageUrl = await storeImage(env, dataUrl, key, url.origin);

    await env.DB.prepare('UPDATE users SET avatar = ? WHERE id = ?').bind(imageUrl, user.id).run();

    const updatedUser = await env.DB.prepare(
      'SELECT id, username, full_name, email, bio, badge, governorate, school, age, avatar, score, is_admin, created_at FROM users WHERE id = ?'
    ).bind(user.id).first();

    return successResponse({ user: { ...updatedUser, is_admin: updatedUser.is_admin === 1 } });
  } catch (e) {
    return errorResponse(e.message);
  }
}

async function handleUserProfileUpdate(request, env) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user) return errorResponse('توكن غير صالح', 401);

  try {
    const body = await request.json();
    const { full_name, email, age, governorate, school, bio } = body;

    if (email && email !== user.email) {
      if (!isValidEmail(email)) return errorResponse('البريد الإلكتروني غير صحيح');
      const emailCheck = await env.DB.prepare(
        'SELECT id FROM users WHERE email = ? AND id != ? AND (deleted_at IS NULL OR deleted_at = "")'
      ).bind(email, user.id).first();
      if (emailCheck) return errorResponse('البريد الإلكتروني مستخدم بالفعل');
    }

    await env.DB.prepare(`
      UPDATE users
      SET full_name = ?, email = ?, age = ?, governorate = ?, school = ?, bio = ?
      WHERE id = ?
    `).bind(
      full_name !== undefined ? full_name : user.full_name,
      email !== undefined ? email : user.email,
      age !== undefined ? age : user.age,
      governorate !== undefined ? governorate : user.governorate,
      school !== undefined ? school : user.school,
      bio !== undefined ? bio : (user.bio || null),
      user.id
    ).run();

    const updatedUser = await env.DB.prepare(
      'SELECT id, username, full_name, email, bio, badge, governorate, school, age, avatar, score, is_admin, created_at FROM users WHERE id = ?'
    ).bind(user.id).first();

    return successResponse({ user: { ...updatedUser, is_admin: updatedUser.is_admin === 1 } });
  } catch (e) {
    return errorResponse(e.message);
  }
}

async function handleUserDelete(request, env) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user) return errorResponse('توكن غير صالح', 401);

  try {
    await env.DB.prepare(
      'UPDATE users SET deleted_at = datetime("now"), token = NULL, token_expires_at = NULL WHERE id = ?'
    ).bind(user.id).run();

    if (user.avatar && env.IMAGES) {
      const key = user.avatar.split('/').pop();
      if (key) await env.IMAGES.delete(key).catch(() => {});
    }

    return successResponse({ message: 'تم حذف الحساب بنجاح' });
  } catch (e) {
    return errorResponse(e.message);
  }
}

async function handleUserLogout(request, env) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  await env.DB.prepare(
    'UPDATE users SET token = NULL, token_expires_at = NULL WHERE token = ?'
  ).bind(token).run();

  return successResponse({ message: 'تم تسجيل الخروج بنجاح' });
}

/**
 * ================================================================
 *  معالجة إحصائيات المستخدم التفصيلية (حفظ وجلب شامل بدون افتراضات)
 * ================================================================
 */
async function handleUserStats(request, env) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user) return errorResponse('توكن غير صالح', 401);

  // POST: حفظ كل بيانات جلسة الاختبار بالتفصيل الدقيق
  if (request.method === 'POST') {
    try {
      const body = await request.json();
      const quizId = body.quiz_id || 'custom';
      
      // الإجابات الصحيحة في هذا النموذج
      const correct = parseInt(body.correct_answers !== undefined ? body.correct_answers : body.score, 10) || 0;
      // إجمالي أسئلة هذا النموذج
      const total = parseInt(body.total_questions !== undefined ? body.total_questions : body.total, 10) || 0;
      // الوقت المستغرق بالثواني لهذا النموذج
      const duration = parseInt(body.duration_seconds !== undefined ? body.duration_seconds : body.time_spent, 10) || 0;
      // الدقة لهذا النموذج
      const percentage = total > 0 ? Math.round((correct / total) * 100) : 0;
      // سجل الإجابات التفصيلي
      const answers = body.answers ? JSON.stringify(body.answers) : '[]';

      // 1. تسجيل النتيجة في جدول results
      await env.DB.prepare(`
        INSERT INTO results (user_id, quiz_id, score, total, percentage, answers, time_spent, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `).bind(user.id, quizId, correct, total, percentage, answers, duration).run();

      // 2. تحديث رصيد النقاط الإجمالي للمستخدم في جدول users مباشرة (10 نقاط لكل سؤال صحيح)
      await env.DB.prepare(`
        UPDATE users 
        SET score = (SELECT COALESCE(SUM(score * 10), 0) FROM results WHERE user_id = ?)
        WHERE id = ?
      `).bind(user.id, user.id).run();

      return successResponse({ 
        message: 'تم حفظ كافة بيانات النموذج وتحديث الإحصائيات بنجاح',
        saved: {
          quiz_id: quizId,
          correct_answers: correct,
          total_questions: total,
          percentage,
          duration_seconds: duration
        }
      });
    } catch (e) {
      return errorResponse(e.message);
    }
  }

  // GET: جلب كافة الإحصائيات المحسوبة من قاعدة البيانات مباشرة
  if (request.method === 'GET') {
    try {
      // 1. الإحصائيات التراكمية الكلية للمستخدم
      const statsStmt = await env.DB.prepare(`
        SELECT 
          COUNT(*) as total_quizzes,
          COALESCE(SUM(total), 0) as total_questions,
          COALESCE(SUM(score), 0) as total_correct,
          COALESCE(AVG(percentage), 0) as avg_accuracy,
          COALESCE(SUM(score * 10), 0) as total_score,
          COALESCE(SUM(time_spent), 0) as total_duration
        FROM results 
        WHERE user_id = ?
      `).bind(user.id);
      const stats = await statsStmt.first();

      // 2. تفصيل كل قسم تعليمي (عدد النماذج، الأسئلة، الدقة، والوقت)
      const catStmt = await env.DB.prepare(`
        SELECT 
          quiz_id, 
          COUNT(*) as quizzes_count, 
          SUM(total) as total_questions,
          SUM(score) as total_correct,
          AVG(percentage) as avg_accuracy,
          SUM(time_spent) as total_duration
        FROM results
        WHERE user_id = ?
        GROUP BY quiz_id
      `).bind(user.id);
      const catResults = await catStmt.all();

      const labelMap = {
        juniors: 'أولمبياد الصغار',
        youth: 'أولمبياد اليافعين',
        grade10: 'الصف العاشر',
        grade9: 'الصف التاسع',
        outstanding7: 'متفوقين - سابع',
        outstanding10: 'متفوقين - عاشر',
        olympiad: 'الأولمبياد العلمي',
        outstanding: 'مدارس المتفوقين',
        general: 'عام'
      };

      const grouped = {};
      catResults.results.forEach(c => {
        const singleWordKey = (c.quiz_id || '').split('_')[0] || 'general';
        const rootName = labelMap[singleWordKey] || singleWordKey;

        if (!grouped[singleWordKey]) {
          grouped[singleWordKey] = {
            id: singleWordKey,
            name: rootName,
            quizzes_count: 0,
            total_questions: 0,
            correct_answers: 0,
            total_score_sum: 0,
            duration_seconds: 0
          };
        }
        grouped[singleWordKey].quizzes_count += c.quizzes_count;
        grouped[singleWordKey].total_questions += c.total_questions;
        grouped[singleWordKey].correct_answers += c.total_correct;
        grouped[singleWordKey].total_score_sum += (c.avg_accuracy * c.quizzes_count);
        grouped[singleWordKey].duration_seconds += (c.total_duration || 0);
      });

      const categories = Object.values(grouped).map(g => ({
        id: g.id,
        name: g.name,
        progress: Math.round(g.quizzes_count > 0 ? (g.total_score_sum / g.quizzes_count) : 0),
        quizzes: g.quizzes_count,
        questions: g.total_questions,
        correct: g.correct_answers,
        duration: g.duration_seconds
      }));

      // 3. أحدث النماذج التي خاضها الطالب مع نتيجتها ووقتها
      const recentStmt = await env.DB.prepare(`
        SELECT id, quiz_id, score as correct_answers, total as total_questions, percentage as accuracy, time_spent as duration_seconds, created_at
        FROM results
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 10
      `).bind(user.id);
      const recent = await recentStmt.all();

      return successResponse({
        total_quizzes: stats?.total_quizzes || 0,        // إجمالي الاختبارات المكتملة
        total_questions: stats?.total_questions || 0,    // إجمالي الأسئلة المحلولة
        correct_answers: stats?.total_correct || 0,      // إجمالي الإجابات الصحيحة
        accuracy: Math.round(stats?.avg_accuracy || 0),  // نسبة الدقة الإجمالية
        total_score: stats?.total_score || 0,            // مجموع النقاط التراكمية
        total_duration: stats?.total_duration || 0,      // إجمالي وقت الحل بالثواني
        total_answers: stats?.total_questions || 0,      // للتوافق العكسي مع الواجهات السابقة
        categories,
        recent_quizzes: recent.results
      });
    } catch (e) {
      return errorResponse(e.message);
    }
  }

  return errorResponse('طريقة غير مدعومة', 405);
}

// نظام المتابعة الشامل
async function handleFollow(request, env, explicitTargetId = null) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);
  const user = await verifyToken(token, env);
  if (!user) return errorResponse('توكن غير صالح', 401);

  try {
    let targetId = explicitTargetId ? parseInt(explicitTargetId, 10) : NaN;
    if (isNaN(targetId)) {
      const url = new URL(request.url);
      targetId = parseInt(url.searchParams.get('targetId') || url.searchParams.get('target_id') || '', 10);
    }
    if (isNaN(targetId)) {
      try {
        const body = await request.json();
        targetId = parseInt(body?.targetId || body?.target_id || body?.id, 10);
      } catch (e) {}
    }

    if (isNaN(targetId)) return errorResponse('معرف المستخدم غير صحيح');
    if (targetId === user.id) return errorResponse('لا يمكن متابعة النفس');

    const target = await env.DB.prepare('SELECT id FROM users WHERE id = ? AND (deleted_at IS NULL OR deleted_at = "")').bind(targetId).first();
    if (!target) return errorResponse('المستخدم غير موجود', 404);

    const existing = await env.DB.prepare('SELECT id FROM follows WHERE follower_id = ? AND following_id = ?').bind(user.id, targetId).first();
    if (existing) return successResponse({ message: 'أنت تتابع هذا المستخدم بالفعل' });

    await env.DB.prepare('INSERT INTO follows (follower_id, following_id, created_at) VALUES (?, ?, datetime("now"))').bind(user.id, targetId).run();
    return successResponse({ message: 'تمت المتابعة بنجاح' });
  } catch (e) {
    return errorResponse(e.message);
  }
}

async function handleUnfollow(request, env, explicitTargetId = null) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);
  const user = await verifyToken(token, env);
  if (!user) return errorResponse('توكن غير صالح', 401);

  try {
    let targetId = explicitTargetId ? parseInt(explicitTargetId, 10) : NaN;
    if (isNaN(targetId)) {
      const url = new URL(request.url);
      targetId = parseInt(url.searchParams.get('targetId') || url.searchParams.get('target_id') || '', 10);
    }
    if (isNaN(targetId)) {
      try {
        const body = await request.json();
        targetId = parseInt(body?.targetId || body?.target_id || body?.id, 10);
      } catch (e) {}
    }

    if (isNaN(targetId)) return errorResponse('معرف المستخدم غير صحيح');

    await env.DB.prepare('DELETE FROM follows WHERE follower_id = ? AND following_id = ?').bind(user.id, targetId).run();
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
    const stmt = await env.DB.prepare('SELECT following_id FROM follows WHERE follower_id = ?').bind(user.id);
    const result = await stmt.all();
    return successResponse({ following: result.results.map(r => r.following_id) });
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
      ORDER BY f.created_at DESC
    `).bind(parseInt(userId, 10));
    const result = await stmt.all();
    const list = result.results.map(u => ({ ...u, is_admin: u.is_admin === 1 }));
    return successResponse(list);
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
      ORDER BY f.created_at DESC
    `).bind(parseInt(userId, 10));
    const result = await stmt.all();
    const list = result.results.map(u => ({ ...u, is_admin: u.is_admin === 1 }));
    return successResponse(list);
  } catch (e) {
    return errorResponse(e.message);
  }
}

// ================================================================
//  PART 3: إدارة بنك الأسئلة (يدعم model_id عبر JOIN مع metadata)
// ================================================================

async function handleQuestions(request, env) {
  const url = new URL(request.url);

  // POST: رفع سؤال جديد
  if (request.method === 'POST') {
    const token = getAuthToken(request);
    if (!token) return errorResponse('غير مصرح', 401);

    const user = await verifyToken(token, env);
    if (!user || (user.is_admin !== 1 && user.is_admin !== true)) {
      return errorResponse('غير مصرح، هذه العملية تتطلب صلاحية مشرف', 403);
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
          question_number: parseInt(formData.get('question_number') || 0, 10),
          text: formData.get('text'),
          options: JSON.parse(formData.get('options') || '[]'),
          correct: parseInt(formData.get('correct'), 10),
          explanation: formData.get('explanation')
        };
        const imageFile = formData.get('image');
        if (imageFile && imageFile.size > 0) {
          if (imageFile.size > 5 * 1024 * 1024) return errorResponse('حجم الصورة يجب أن يكون أقل من 5 ميجابايت', 400);
          const buffer = await imageFile.arrayBuffer();
          imageData = `data:${imageFile.type || 'image/jpeg'};base64,${arrayBufferToBase64(buffer)}`;
        }
      } else {
        body = await request.json();
        imageData = body.image || null;
      }

      const { category, subject, model, question_number, text, options, correct, explanation } = body;
      if (!category || !subject || !model || !text || !options || correct === undefined) {
        return errorResponse('جميع الحقول المطلوبة يجب تعبئتها');
      }

      const metaRow = await env.DB.prepare(
        'SELECT id FROM metadata WHERE category = ? AND subject = ? AND model = ? LIMIT 1'
      ).bind(category, subject, model).first();

      if (!metaRow) {
        return errorResponse(`النموذج "${model}" غير موجود في metadata للفئة "${category}" والمادة "${subject}"`, 400);
      }
      const modelId = metaRow.id;

      let imageUrl = null;
      if (imageData) {
        const key = `question_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
        imageUrl = await storeImage(env, imageData, key, url.origin);
      }

      const existing = await env.DB.prepare(`
        SELECT id FROM questions 
        WHERE category = ? AND subject = ? AND model_id = ? AND question_number = ? AND (deleted_at IS NULL OR deleted_at = "")
      `).bind(category, subject, modelId, question_number || 0).first();

      let qId;
      if (existing) {
        await env.DB.prepare(`
          UPDATE questions 
          SET text = ?, options = ?, correct = ?, explanation = ?, image = COALESCE(?, image)
          WHERE id = ?
        `).bind(text, JSON.stringify(options), correct, explanation || null, imageUrl, existing.id).run();
        qId = existing.id;
      } else {
        await env.DB.prepare(`
          INSERT INTO questions (category, subject, model_id, question_number, text, options, correct, explanation, image, created_by, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        `).bind(
          category, subject, modelId, question_number || 0,
          text, JSON.stringify(options), correct,
          explanation || null, imageUrl || null, user.id
        ).run();

        const result = await env.DB.prepare('SELECT last_insert_rowid() as id').first();
        qId = result ? result.id : null;
      }

      return successResponse({ message: 'تم رفع السؤال بنجاح', id: qId });
    } catch (e) {
      return errorResponse(e.message);
    }
          }
  
  // GET: جلب أسئلة الاختبار
  if (request.method === 'GET') {
    let category = url.searchParams.get('category');
    let subject = url.searchParams.get('subject');
    let model = url.searchParams.get('model');
    const quizId = url.searchParams.get('quiz') || url.searchParams.get('quizId');
    const mixed = url.searchParams.get('mixed');

    if (mixed) {
      try {
        let mixedQuery = `
          SELECT q.id, q.category, q.subject, m.model, q.question_number, q.text, q.options,
                 q.correct, q.explanation, q.image, m.display_name AS model_name, q.created_at
          FROM questions q
          JOIN metadata m ON q.model_id = m.id
          WHERE (q.deleted_at IS NULL OR q.deleted_at = "")
        `;
        const mixedParams = [];
        if (mixed !== 'full') {
          mixedQuery += ` AND (q.category = ? OR q.category LIKE ?)`;
          mixedParams.push(mixed, `${mixed}%`);
        }
        mixedQuery += ` ORDER BY RANDOM() LIMIT 30`;

        const stmt = await env.DB.prepare(mixedQuery).bind(...mixedParams);
        const questions = await stmt.all();

        const processed = questions.results.map(q => {
          let opts = q.options;
          if (typeof opts === 'string') {
            try { opts = JSON.parse(opts); } catch (e) { opts = []; }
          }
          return { ...q, options: opts };
        });

        return successResponse({ questions: processed });
      } catch (e) {
        return errorResponse(e.message);
      }
    }

    if (!category && quizId) {
      const parts = quizId.split('_');
      if (parts.length >= 3) {
        category = parts[0];
        subject = parts[1];
        model = parts.slice(2).join('_');
      }
    }

    if (!category || !subject) {
      return errorResponse('الفئة والمادة مطلوبان', 400);
    }

    try {
      let query = `
        SELECT q.id, q.category, q.subject, m.model, q.question_number, q.text, q.options,
               q.correct, q.explanation, q.image, m.display_name AS model_name, q.created_at
        FROM questions q
        JOIN metadata m ON q.model_id = m.id
        WHERE (q.deleted_at IS NULL OR q.deleted_at = "")
          AND q.category = ?
          AND q.subject = ?
      `;
      const params = [category, subject];

      if (model && model !== 'random') {
        query += ' AND m.model = ? ORDER BY q.question_number ASC';
        params.push(model);
      } else {
        query += ' ORDER BY RANDOM() LIMIT 30';
      }

      const stmt = await env.DB.prepare(query).bind(...params);
      const questions = await stmt.all();

      const processed = questions.results.map(q => {
        let opts = q.options;
        if (typeof opts === 'string') {
          try { opts = JSON.parse(opts); } catch (e) { opts = []; }
        }
        return { ...q, options: opts };
      });

      return successResponse({ questions: processed });
    } catch (e) {
      return errorResponse(e.message);
    }
  }

  return errorResponse('طريقة غير مدعومة', 405);
}

async function resolveQuestionRow(idStr, env) {
  const numericId = parseInt(idStr, 10);
  if (!isNaN(numericId)) {
    return await env.DB.prepare(`
      SELECT q.*, m.model, m.display_name AS model_name
      FROM questions q
      JOIN metadata m ON q.model_id = m.id
      WHERE q.id = ? AND (q.deleted_at IS NULL OR q.deleted_at = "")
    `).bind(numericId).first();
  }

  const parts = idStr.split('_');
  if (parts.length < 4) return null;

  const qnPart = parts[parts.length - 1].replace(/^q/, '');
  const model = parts[parts.length - 2];
  const subject = parts[parts.length - 3];
  const category = parts.slice(0, parts.length - 3).join('_');
  const questionNumber = parseInt(qnPart, 10);

  if (isNaN(questionNumber)) return null;

  return await env.DB.prepare(`
    SELECT q.*, m.model, m.display_name AS model_name
    FROM questions q
    JOIN metadata m ON q.model_id = m.id
    WHERE q.category = ? AND q.subject = ? AND m.model = ? AND q.question_number = ?
      AND (q.deleted_at IS NULL OR q.deleted_at = "")
    LIMIT 1
  `).bind(category, subject, model, questionNumber).first();
}

async function handleGetSingleQuestion(request, env, id) {
  try {
    const question = await resolveQuestionRow(id, env);
    if (!question) return errorResponse('السؤال غير موجود', 404);

    if (question.options && typeof question.options === 'string') {
      try { question.options = JSON.parse(question.options); } catch (e) { question.options = []; }
    }

    return successResponse(question);
  } catch (e) {
    return errorResponse(e.message);
  }
}

async function handleQuestionFullUpdate(request, env, id) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user || (user.is_admin !== 1 && user.is_admin !== true)) {
    return errorResponse('غير مصرح، تحتاج صلاحية مشرف', 403);
  }

  try {
    const existing = await resolveQuestionRow(id, env);
    if (!existing) return errorResponse('السؤال غير موجود', 404);

    const targetNumericId = existing.id;
    const url = new URL(request.url);

    let body;
    let imageData = null;
    const contentType = request.headers.get('Content-Type') || '';

    if (contentType.includes('multipart/form-data')) {
      const formData = await request.formData();
      body = {
        category: formData.get('category'),
        subject: formData.get('subject'),
        model: formData.get('model'),
        question_number: parseInt(formData.get('question_number') || 0, 10),
        text: formData.get('text'),
        options: JSON.parse(formData.get('options') || '[]'),
        correct: parseInt(formData.get('correct'), 10),
        explanation: formData.get('explanation')
      };
      const imageFile = formData.get('image');
      if (imageFile && imageFile.size > 0) {
        if (imageFile.size > 5 * 1024 * 1024) return errorResponse('حجم الصورة يجب أن يكون أقل من 5 ميجابايت', 400);
        const buffer = await imageFile.arrayBuffer();
        imageData = `data:${imageFile.type || 'image/jpeg'};base64,${arrayBufferToBase64(buffer)}`;
      }
    } else {
      body = await request.json();
      imageData = body.image || null;
    }

    const { category, subject, model, question_number, text, options, correct, explanation } = body;
    if (!category || !subject || !model || !text || !options || correct === undefined) {
      return errorResponse('جميع الحقول المطلوبة يجب تعبئتها');
    }

    const metaRow = await env.DB.prepare(
      'SELECT id FROM metadata WHERE category = ? AND subject = ? AND model = ? LIMIT 1'
    ).bind(category, subject, model).first();

    if (!metaRow) {
      return errorResponse(`النموذج "${model}" غير موجود في metadata`, 400);
    }
    const modelId = metaRow.id;

    let imageUrl = null;
    if (imageData) {
      const key = `question_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
      imageUrl = await storeImage(env, imageData, key, url.origin);
    }

    let updateQuery = `
      UPDATE questions 
      SET category = ?, subject = ?, model_id = ?, question_number = ?, 
          text = ?, options = ?, correct = ?, explanation = ?
    `;
    const params = [category, subject, modelId, question_number, text, JSON.stringify(options), correct, explanation || null];

    if (imageUrl) {
      updateQuery += `, image = ?`;
      params.push(imageUrl);
    }

    updateQuery += ' WHERE id = ?';
    params.push(targetNumericId);

    await env.DB.prepare(updateQuery).bind(...params).run();

    const updated = await env.DB.prepare(`
      SELECT q.*, m.model, m.display_name AS model_name
      FROM questions q
      JOIN metadata m ON q.model_id = m.id
      WHERE q.id = ?
    `).bind(targetNumericId).first();

    if (updated && updated.options && typeof updated.options === 'string') {
      try { updated.options = JSON.parse(updated.options); } catch (e) { updated.options = []; }
    }

    return successResponse({ message: 'تم تحديث السؤال بنجاح', question: updated });
  } catch (e) {
    return errorResponse(e.message);
  }
}

async function handleQuestionDelete(request, env, id) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user || (user.is_admin !== 1 && user.is_admin !== true)) {
    return errorResponse('غير مصرح، تحتاج صلاحية مشرف', 403);
  }

  try {
    const existing = await resolveQuestionRow(id, env);
    if (!existing) return errorResponse('السؤال غير موجود أو تم حذفه مسبقاً', 404);

    await env.DB.prepare(
      'UPDATE questions SET deleted_at = datetime("now") WHERE id = ?'
    ).bind(existing.id).run();

    return successResponse({ message: 'تم حذف السؤال بنجاح' });
  } catch (e) {
    return errorResponse(e.message);
  }
}

// ================================================================
//  PART 4: المجتمع، التفاعل والمتصدرين المحدثين
// ================================================================

async function handlePosts(request, env) {
  const url = new URL(request.url);

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
          if (imageFile.size > 5 * 1024 * 1024) return errorResponse('حجم الصورة يجب أن يكون أقل من 5 ميجابايت', 400);
          const buffer = await imageFile.arrayBuffer();
          imageData = `data:${imageFile.type || 'image/jpeg'};base64,${arrayBufferToBase64(buffer)}`;
        }
      } else {
        const body = await request.json();
        title = body.title;
        content = body.content;
        category = body.category || 'general';
        imageData = body.image || null;
      }

      if (!title || !content) return errorResponse('العنوان والمحتوى مطلوبان');

      let imageUrl = null;
      if (imageData) {
        const key = `post_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
        imageUrl = await storeImage(env, imageData, key, url.origin);
      }

      await env.DB.prepare(`
        INSERT INTO posts (user_id, title, content, category, image, created_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
      `).bind(user.id, title, content, category, imageUrl).run();

      return successResponse({ message: 'تم نشر المنشور بنجاح' });
    } catch (e) {
      return errorResponse(e.message);
    }
  }

  if (request.method === 'GET') {
    try {
      const targetUserId = url.searchParams.get('userId') || url.searchParams.get('user_id');
      const token = getAuthToken(request);
      const currentUser = token ? await verifyToken(token, env) : null;

      let query = `
        SELECT 
          p.id, p.title, p.content, p.category, p.image, p.created_at,
          u.id as user_id, u.full_name, u.username, u.avatar, u.badge, u.is_admin,
          (SELECT COUNT(*) FROM post_likes pl WHERE pl.post_id = p.id) as likes_count,
          (SELECT COUNT(*) FROM post_comments pc WHERE pc.post_id = p.id) as comments_count
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE (u.deleted_at IS NULL OR u.deleted_at = "")
      `;
      const params = [];

      if (targetUserId) {
        query += ` AND p.user_id = ?`;
        params.push(parseInt(targetUserId, 10));
      }

      query += ` ORDER BY p.created_at DESC`;

      const stmt = await env.DB.prepare(query).bind(...params);
      const posts = await stmt.all();

      let userLikedSet = new Set();
      if (currentUser) {
        const likesStmt = await env.DB.prepare('SELECT post_id FROM post_likes WHERE user_id = ?').bind(currentUser.id);
        const userLikes = await likesStmt.all();
        userLikedSet = new Set(userLikes.results.map(l => l.post_id));
      }

      const list = posts.results.map(p => ({
        ...p,
        is_admin: p.is_admin === 1 || p.is_admin === true || p.is_admin === '1',
        is_liked: userLikedSet.has(p.id)
      }));

      return successResponse({ posts: list });
    } catch (e) {
      return errorResponse(e.message);
    }
  }

  return errorResponse('طريقة غير مدعومة', 405);
}

async function handlePostLike(request, env, postId) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user) return errorResponse('توكن غير صالح', 401);

  const pId = parseInt(postId, 10);
  if (isNaN(pId)) return errorResponse('معرف المنشور غير صحيح');

  try {
    const existing = await env.DB.prepare('SELECT 1 FROM post_likes WHERE post_id = ? AND user_id = ?').bind(pId, user.id).first();

    let isLiked = false;
    if (existing) {
      await env.DB.prepare('DELETE FROM post_likes WHERE post_id = ? AND user_id = ?').bind(pId, user.id).run();
      isLiked = false;
    } else {
      await env.DB.prepare('INSERT INTO post_likes (post_id, user_id, created_at) VALUES (?, ?, datetime("now"))').bind(pId, user.id).run();
      isLiked = true;
    }

    const countRes = await env.DB.prepare('SELECT COUNT(*) as count FROM post_likes WHERE post_id = ?').bind(pId).first();

    return successResponse({
      is_liked: isLiked,
      likes_count: countRes?.count || 0
    });
  } catch (e) {
    return errorResponse(e.message);
  }
}

async function handlePostLikers(request, env, postId) {
  const pId = parseInt(postId, 10);
  if (isNaN(pId)) return errorResponse('معرف المنشور غير صحيح');

  try {
    const stmt = await env.DB.prepare(`
      SELECT u.id, u.username, u.full_name, u.avatar, u.badge, u.is_admin
      FROM users u
      JOIN post_likes pl ON u.id = pl.user_id
      WHERE pl.post_id = ? AND (u.deleted_at IS NULL OR u.deleted_at = "")
      ORDER BY pl.created_at DESC
    `).bind(pId);
    const result = await stmt.all();

    const users = result.results.map(u => ({
      ...u,
      is_admin: u.is_admin === 1 || u.is_admin === true || u.is_admin === '1'
    }));

    return successResponse(users);
  } catch (e) {
    return errorResponse(e.message);
  }
}

async function handlePostComments(request, env, postId) {
  const pId = parseInt(postId, 10);
  if (isNaN(pId)) return errorResponse('معرف المنشور غير صحيح');

  if (request.method === 'GET') {
    try {
      const stmt = await env.DB.prepare(`
        SELECT 
          c.id, c.content, c.created_at,
          u.id as user_id, u.username, u.full_name, u.avatar, u.is_admin
        FROM post_comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.post_id = ? AND (u.deleted_at IS NULL OR u.deleted_at = "")
        ORDER BY c.created_at ASC
      `).bind(pId);
      const comments = await stmt.all();

      const list = comments.results.map(c => ({
        ...c,
        is_admin: c.is_admin === 1 || c.is_admin === true || c.is_admin === '1'
      }));

      return successResponse(list);
    } catch (e) {
      return errorResponse(e.message);
    }
  }

  if (request.method === 'POST') {
    const token = getAuthToken(request);
    if (!token) return errorResponse('غير مصرح', 401);

    const user = await verifyToken(token, env);
    if (!user) return errorResponse('توكن غير صالح', 401);

    try {
      const body = await request.json();
      const content = (body.content || '').trim();
      if (!content) return errorResponse('محتوى التعليق مطلوب');

      await env.DB.prepare(`
        INSERT INTO post_comments (post_id, user_id, content, created_at)
        VALUES (?, ?, ?, datetime("now"))
      `).bind(pId, user.id, content).run();

      return successResponse({ message: 'تمت إضافة التعليق بنجاح' });
    } catch (e) {
      return errorResponse(e.message);
    }
  }

  return errorResponse('طريقة غير مدعومة', 405);
}

async function handleResults(request, env) {
  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);
  const user = await verifyToken(token, env);
  if (!user) return errorResponse('توكن غير صالح', 401);

  if (request.method === 'POST') {
    try {
      const body = await request.json();
      const { quiz_id, score, total, percentage, answers, time_spent } = body;

      await env.DB.prepare(`
        INSERT INTO results (user_id, quiz_id, score, total, percentage, answers, time_spent, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `).bind(user.id, quiz_id, score, total, percentage, JSON.stringify(answers || []), time_spent || null).run();

      return successResponse({ message: 'تم حفظ النتيجة' });
    } catch (e) {
      return errorResponse(e.message);
    }
  }

  if (request.method === 'GET') {
    try {
      const stmt = await env.DB.prepare(`
        SELECT id, quiz_id, score, total, percentage, answers, time_spent, created_at
        FROM results 
        WHERE user_id = ? 
        ORDER BY created_at DESC
      `).bind(user.id);
      const results = await stmt.all();
      return successResponse({ results: results.results });
    } catch (e) {
      return errorResponse(e.message);
    }
      }
  return errorResponse('طريقة غير مدعومة', 405);
}

/**
 * ================================================================
 *  لوحة المتصدرين الشاملة والمحدثة بالكامل مع كافة البيانات الحقيقية
 * ================================================================
 */
async function handleLeaderboard(request, env) {
  const url = new URL(request.url);
  const category = url.searchParams.get('category');

  try {
    let query = `
      SELECT u.id, u.username, u.full_name, u.badge, u.avatar, u.is_admin,
             COUNT(r.id) as total_quizzes,
             COALESCE(SUM(r.total), 0) as total_questions,
             COALESCE(SUM(r.score), 0) as total_correct,
             COALESCE(SUM(r.score * 10), 0) as total_points,
             COALESCE(AVG(r.percentage), 0) as avg_accuracy,
             COALESCE(SUM(r.time_spent), 0) as total_duration
      FROM users u
      LEFT JOIN results r ON u.id = r.user_id
      WHERE (u.deleted_at IS NULL OR u.deleted_at = "")
    `;
    const params = [];

    if (category && category !== 'all') {
      if (category === 'olympiad') {
        query += ` AND (r.quiz_id LIKE 'olympiad%' OR r.quiz_id LIKE 'juniors%' OR r.quiz_id LIKE 'youth%' OR r.quiz_id LIKE 'grade10%')`;
      } else if (category === 'outstanding') {
        query += ` AND (r.quiz_id LIKE 'outstanding%' OR r.quiz_id LIKE 'outstanding7%' OR r.quiz_id LIKE 'outstanding10%')`;
      } else {
        query += ` AND r.quiz_id LIKE ?`;
        params.push(`${category}%`);
      }
    }

    query += ` GROUP BY u.id HAVING total_quizzes > 0 ORDER BY total_points DESC, avg_accuracy DESC LIMIT 100`;

    const stmt = await env.DB.prepare(query).bind(...params);
    const data = await stmt.all();

    // إرجاع كل الحقول المحسوبة من قاعدة البيانات بدون أي أصفار مصطنعة
    const leaderboard = data.results.map(u => ({
      id: u.id,
      username: u.username,
      full_name: u.full_name,
      badge: u.badge || 'none',
      avatar: u.avatar || null,
      is_admin: u.is_admin === 1 || u.is_admin === true || u.is_admin === '1',
      score: Math.round(u.total_points || 0),           // إجمالي النقاط (10 نقاط لكل سؤال صحيح)
      total_quizzes: u.total_quizzes || 0,             // عدد الاختبارات المنجزة
      total_questions: u.total_questions || 0,         // إجمالي الأسئلة التي خاضها
      correct_answers: u.total_correct || 0,           // مجموع الإجابات الصحيحة
      accuracy: Math.round(u.avg_accuracy || 0),       // متوسط نسبة الدقة
      duration_seconds: u.total_duration || 0          // إجمالي الوقت المستغرق بالثواني
    }));

    return successResponse({ leaderboard });
  } catch (e) {
    return errorResponse(e.message);
  }
}

async function handleSearch(request, env) {
  const url = new URL(request.url);
  const query = url.searchParams.get('q');

  if (!query || query.trim().length < 2) {
    return successResponse({ questions: [], posts: [], users: [] });
  }

  const searchTerm = `%${query.trim()}%`;

  try {
    const qStmt = await env.DB.prepare(`
      SELECT q.id, q.text as question_text, q.category, q.subject, m.model, q.options
      FROM questions q
      JOIN metadata m ON q.model_id = m.id
      WHERE q.text LIKE ? AND (q.deleted_at IS NULL OR q.deleted_at = "")
      LIMIT 10
    `).bind(searchTerm);
    const questions = await qStmt.all();

    const pStmt = await env.DB.prepare(`
      SELECT p.id, p.title, p.content, p.category, u.full_name, u.username, u.avatar
      FROM posts p
      JOIN users u ON p.user_id = u.id
      WHERE (p.title LIKE ? OR p.content LIKE ?) AND (u.deleted_at IS NULL OR u.deleted_at = "")
      LIMIT 10
    `).bind(searchTerm, searchTerm);
    const posts = await pStmt.all();

    const uStmt = await env.DB.prepare(`
      SELECT id, username, full_name, badge, avatar, is_admin
      FROM users
      WHERE (username LIKE ? OR full_name LIKE ?) AND (deleted_at IS NULL OR deleted_at = "")
      LIMIT 10
    `).bind(searchTerm, searchTerm);
    const users = await uStmt.all();

    return successResponse({
      questions: questions.results.map(q => {
        let opts = q.options;
        if (typeof opts === 'string') {
          try { opts = JSON.parse(opts); } catch (e) { opts = []; }
        }
        return { ...q, options: opts };
      }),
      posts: posts.results,
      users: users.results.map(u => ({ ...u, is_admin: u.is_admin === 1 }))
    });
  } catch (e) {
    return errorResponse(e.message);
  }
}

// ================================================================
//  PART 5: البيانات الوصفية (Metadata)
// ================================================================

async function handleMetadata(request, env) {
  const url = new URL(request.url);
  const category = url.searchParams.get('category');
  const subject = url.searchParams.get('subject');

  try {
    let query = `SELECT id, category, subject, model, display_name, icon_class, sort_order FROM metadata`;
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

    if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
    query += ' ORDER BY sort_order ASC, model ASC';

    const stmt = await env.DB.prepare(query).bind(...params);
    const result = await stmt.all();

    const data = {};
    result.results.forEach(row => {
      if (!data[row.subject]) data[row.subject] = [];
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

async function handleMetadataManagement(request, env) {
  const url = new URL(request.url);
  const method = request.method;

  const token = getAuthToken(request);
  if (!token) return errorResponse('غير مصرح', 401);

  const user = await verifyToken(token, env);
  if (!user || (user.is_admin !== 1 && user.is_admin !== true)) {
    return errorResponse('غير مصرح، تحتاج صلاحية مشرف', 403);
  }

  if (method === 'POST') {
    try {
      const body = await request.json();
      const { category, subject, model, display_name, icon_class } = body;

      if (!category || !subject || !model || !display_name) {
        return errorResponse('جميع الحقول المطلوبة يجب تعبئتها');
      }

      const check = await env.DB.prepare(
        'SELECT id FROM metadata WHERE category = ? AND subject = ? AND model = ?'
      ).bind(category, subject, model).first();

      if (check) return errorResponse('هذا النموذج موجود بالفعل لهذا القسم والمادة');

      await env.DB.prepare(`
        INSERT INTO metadata (category, subject, model, display_name, icon_class, sort_order)
        VALUES (?, ?, ?, ?, ?, (SELECT COALESCE(MAX(sort_order), 0) + 1 FROM metadata WHERE category = ? AND subject = ?))
      `).bind(category, subject, model, display_name, icon_class || null, category, subject).run();

      return successResponse({
        message: 'تم إضافة النموذج بنجاح',
        model: { category, subject, model, display_name, icon_class }
      });
    } catch (e) {
      return errorResponse(e.message);
    }
  }

  if (method === 'DELETE') {
    try {
      const id = url.searchParams.get('id');
      if (!id) return errorResponse('معرف النموذج مطلوب');

      await env.DB.prepare('DELETE FROM metadata WHERE id = ?').bind(parseInt(id, 10)).run();
      return successResponse({ message: 'تم حذف النموذج بنجاح' });
    } catch (e) {
      return errorResponse(e.message);
    }
  }

  return errorResponse('طريقة غير مدعومة', 405);
}

// ================================================================
//  PART 6: الموجه العام للطلبات (Main Router)
// ================================================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    try {
      // 1. مسارات المستخدمين والمصادقة
      if (path === '/api/users/login' && method === 'POST') return await handleUserLogin(request, env);
      if (path === '/api/users/signup' && method === 'POST') return await handleUserSignup(request, env);
      if (path === '/api/users/me' && method === 'GET') return await handleUserMe(request, env);
      if (path === '/api/users/profile' && method === 'GET') return await handleUserProfileById(request, env);
      if (path === '/api/users/profile' && method === 'PUT') return await handleUserProfileUpdate(request, env);
      if (path === '/api/users/avatar' && method === 'POST') return await handleAvatarUpload(request, env);
      if (path === '/api/users/verify' && method === 'GET') return await handleVerifyToken(request, env);
      if (path === '/api/users/refresh' && method === 'POST') return await handleRefreshToken(request, env);
      if (path === '/api/users/logout' && method === 'POST') return await handleUserLogout(request, env);
      if (path === '/api/users/delete' && method === 'DELETE') return await handleUserDelete(request, env);
      if (path === '/api/users/stats' && (method === 'GET' || method === 'POST')) return await handleUserStats(request, env);

      if (path.match(/^\/api\/users\/(\d+)\/posts$/) && method === 'GET') {
        const id = path.split('/')[3];
        url.searchParams.set('userId', id);
        return await handlePosts(new Request(url.toString(), request), env);
      }

      if (path === '/api/users/follow' && method === 'POST') return await handleFollow(request, env);
      if (path.match(/^\/api\/users\/(\d+)\/follow$/) && method === 'POST') {
        const targetId = path.split('/')[3];
        return await handleFollow(request, env, targetId);
      }
      if (path === '/api/users/unfollow' && (method === 'DELETE' || method === 'POST')) return await handleUnfollow(request, env);
      if (path === '/api/users/me/following' && method === 'GET') return await handleUserFollowing(request, env);
      if (path.match(/^\/api\/users\/(\d+)\/followers$/) && method === 'GET') {
        const id = path.split('/')[3];
        return await handleFollowersList(request, env, id);
      }
      if (path.match(/^\/api\/users\/(\d+)\/following$/) && method === 'GET') {
        const id = path.split('/')[3];
        return await handleFollowingList(request, env, id);
      }

      // 2. مسارات بنك الأسئلة
      if ((path === '/api/questions' || path === '/api/questions/upload') && (method === 'GET' || method === 'POST')) {
        return await handleQuestions(request, env);
      }
      if (path.startsWith('/api/questions/') && method === 'GET') {
        const id = path.replace('/api/questions/', '');
        return await handleGetSingleQuestion(request, env, decodeURIComponent(id));
      }
      if (path.startsWith('/api/questions/') && method === 'PUT') {
        const id = path.replace('/api/questions/', '');
        return await handleQuestionFullUpdate(request, env, decodeURIComponent(id));
      }
      if (path.startsWith('/api/questions/') && method === 'DELETE') {
        const id = path.replace('/api/questions/', '');
        return await handleQuestionDelete(request, env, decodeURIComponent(id));
      }

      // 3. مسارات المنشورات والتفاعل المجتمعي
      if (path.match(/^\/api\/posts\/(\d+)\/like$/) && method === 'POST') {
        const postId = path.split('/')[3];
        return await handlePostLike(request, env, postId);
      }
      if (path.match(/^\/api\/posts\/(\d+)\/likes$/) && method === 'GET') {
        const postId = path.split('/')[3];
        return await handlePostLikers(request, env, postId);
      }
      if (path.match(/^\/api\/posts\/(\d+)\/comments$/)) {
        const postId = path.split('/')[3];
        return await handlePostComments(request, env, postId);
      }
      if (path === '/api/posts') return await handlePosts(request, env);

      // 4. مسارات النتائج، لوحة المتصدرين والبحث
      if (path === '/api/results') return await handleResults(request, env);
      if (path === '/api/leaderboard' && method === 'GET') return await handleLeaderboard(request, env);
      if (path === '/api/search' && method === 'GET') return await handleSearch(request, env);

      // 5. البيانات الوصفية (Metadata)
      if (path === '/api/metadata' && method === 'GET') return await handleMetadata(request, env);
      if (path === '/api/metadata/manage') return await handleMetadataManagement(request, env);

      // 6. جلب الصور المرفوعة من KV
      if (path.startsWith('/api/images/')) {
        const key = path.replace('/api/images/', '');
        if (!env.IMAGES) return errorResponse('تخزين الصور غير متوفر', 503);
        const imageData = await getImage(env, key);
        if (!imageData) return errorResponse('الصورة غير موجودة', 404);

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

      return errorResponse('المسار غير موجود', 404);
    } catch (e) {
      console.error('[Worker Fatal Error]:', e);
      return errorResponse('حدث خطأ داخلي في الخادم', 500);
    }
  }
};
