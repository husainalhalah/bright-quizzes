/**
 * ================================================================
 * Bright Quizzes - Script الرئيسي للمصادقة وإدارة الجلسات
 * ================================================================
 * 
 * يوفر هذا الملف:
 * 1. إدارة المصادقة والجلسات الدائمة (Persistent Sessions)
 * 2. حماية الصفحات الحساسة دون الحاجة للتحقق من الخادم عند التحميل
 * 3. إدارة واجهة المستخدم (UI) بناءً على حالة المصادقة
 * 4. عرض الرسائل والتنبيهات (Toast)
 * ================================================================
 */

// ================================================================
// 1. ToastManager - إدارة الرسائل والتنبيهات
// ================================================================

const ToastManager = {
  /**
   * عرض رسالة نجاح
   * @param {string} message - نص الرسالة
   * @param {number} duration - مدة عرض الرسالة (ميلي ثانية)
   */
  success(message, duration = 3000) {
    this.show(message, 'success', duration);
  },

  /**
   * عرض رسالة خطأ
   * @param {string} message - نص الرسالة
   * @param {number} duration - مدة عرض الرسالة (ميلي ثانية)
   */
  error(message, duration = 4000) {
    this.show(message, 'error', duration);
  },

  /**
   * عرض رسالة تحذير
   * @param {string} message - نص الرسالة
   * @param {number} duration - مدة عرض الرسالة (ميلي ثانية)
   */
  warning(message, duration = 3500) {
    this.show(message, 'warning', duration);
  },

  /**
   * عرض رسالة عامة
   * @param {string} message - نص الرسالة
   * @param {string} type - نوع الرسالة (success, error, warning, info)
   * @param {number} duration - مدة عرض الرسالة (ميلي ثانية)
   */
  show(message, type = 'info', duration = 3000) {
    // تحقق من وجود الحاوية
    let container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      container.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 9999;
        max-width: 400px;
      `;
      document.body.appendChild(container);
    }

    // إنشاء عنصر الرسالة
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
      margin-bottom: 10px;
      padding: 15px 20px;
      border-radius: 4px;
      font-size: 14px;
      animation: slideIn 0.3s ease-in-out;
      ${type === 'success' ? 'background-color: #4caf50; color: white;' : ''}
      ${type === 'error' ? 'background-color: #f44336; color: white;' : ''}
      ${type === 'warning' ? 'background-color: #ff9800; color: white;' : ''}
      ${type === 'info' ? 'background-color: #2196f3; color: white;' : ''}
      box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    `;

    container.appendChild(toast);

    // حذف الرسالة بعد المدة المحددة
    setTimeout(() => {
      toast.style.animation = 'slideOut 0.3s ease-in-out';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }
};

// ================================================================
// 2. UserManager - إدارة المستخدمين والمصادقة
// ================================================================

const UserManager = {
  // الحقول الخاصة
  currentUser: null,
  authToken: null,
  apiBaseUrl: 'https://bright-quizzes.brightquizzes.workers.dev', // عدّل هذا إذا لزم الأمر

  /**
   * تهيئة مدير المستخدمين عند تحميل الصفحة
   */
  init() {
    // قراءة البيانات من localStorage
    this.loadFromStorage();

    // تحديث واجهة المستخدم بناءً على حالة المصادقة
    this.updateUI();

    // تحديث البيانات من الخادم (اختياري، لا يؤثر على الجلسة المحلية)
    if (this.isAuthenticated()) {
      this.fetchUserFromAPI().catch(() => {
        // في حالة فشل الطلب، نستمر باستخدام البيانات المحلية
      });
    }
  },

  /**
   * قراءة بيانات المستخدم والتوكن من localStorage
   */
  loadFromStorage() {
    try {
      const token = localStorage.getItem('auth_token');
      const userStr = localStorage.getItem('currentUser');

      this.authToken = token;
      this.currentUser = userStr ? JSON.parse(userStr) : null;
    } catch (e) {
      console.error('Error loading user from storage:', e);
      this.authToken = null;
      this.currentUser = null;
    }
  },

  /**
   * حفظ بيانات المستخدم والتوكن في localStorage
   */
  saveToStorage() {
    try {
      if (this.authToken) {
        localStorage.setItem('auth_token', this.authToken);
      } else {
        localStorage.removeItem('auth_token');
      }

      if (this.currentUser) {
        localStorage.setItem('currentUser', JSON.stringify(this.currentUser));
      } else {
        localStorage.removeItem('currentUser');
      }
    } catch (e) {
      console.error('Error saving user to storage:', e);
    }
  },

  /**
   * التحقق من حالة المصادقة (بناءً على وجود التوكن محلياً فقط)
   * @returns {boolean} true إذا كان المستخدم مسجلاً
   */
  isAuthenticated() {
    return !!this.authToken && !!this.currentUser;
  },

  /**
   * جلب بيانات المستخدم من الخادم (اختياري للتحديث)
   * في حالة 401، لا نسجل الخروج بل نعرض تنبيه فقط
   */
  async fetchUserFromAPI() {
    if (!this.authToken) {
      return null;
    }

    try {
      const response = await fetch(`${this.apiBaseUrl}/api/users/me`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.authToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.status === 401) {
        // التوكن منتهي الصلاحية على الخادم - عرض تنبيه فقط
        ToastManager.warning('انتهت صلاحية جلستك. يرجى تسجيل الدخول مرة أخرى.');
        return null;
      }

      if (!response.ok) {
        throw new Error(`Server error: ${response.status}`);
      }

      const data = await response.json();
      if (data.success && data.data) {
        // تحديث البيانات المحلية
        this.currentUser = data.data;
        this.saveToStorage();
        this.updateUI();
        return data.data;
      }

      return null;
    } catch (error) {
      // في حالة فشل الشبكة، نستمر باستخدام البيانات المحلية
      console.warn('Could not fetch user from API, using cached data:', error);
      return this.currentUser;
    }
  },

  /**
   * تسجيل دخول المستخدم
   * @param {string} username - اسم المستخدم
   * @param {string} password - كلمة المرور
   * @returns {Promise<object>} بيانات المستخدم والتوكن
   */
  async login(username, password) {
    try {
      const response = await fetch(`${this.apiBaseUrl}/api/users/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'فشل تسجيل الدخول');
      }

      // حفظ التوكن وبيانات المستخدم
      this.authToken = data.data.token;
      this.currentUser = data.data.user;
      this.saveToStorage();
      this.updateUI();

      ToastManager.success('تم تسجيل الدخول بنجاح');
      return data.data;
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    }
  },

  /**
   * إنشاء حساب جديد
   * @param {object} userData - بيانات المستخدم الجديد
   * @returns {Promise<object>} بيانات المستخدم الجديد والتوكن
   */
  async signup(userData) {
    try {
      const response = await fetch(`${this.apiBaseUrl}/api/users/signup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(userData)
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'فشل إنشاء الحساب');
      }

      // حفظ التوكن وبيانات المستخدم
      this.authToken = data.data.token;
      this.currentUser = data.data.user;
      this.saveToStorage();
      this.updateUI();

      ToastManager.success('تم إنشاء الحساب بنجاح');
      return data.data;
    } catch (error) {
      console.error('Signup error:', error);
      throw error;
    }
  },

  /**
   * تسجيل الخروج
   */
  async logout() {
    try {
      if (this.authToken) {
        // محاولة إخبار الخادم بتسجيل الخروج
        await fetch(`${this.apiBaseUrl}/api/users/logout`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.authToken}`,
            'Content-Type': 'application/json'
          }
        }).catch(() => {
          // حتى إذا فشل الطلب، نستمر في تسجيل الخروج محلياً
        });
      }

      // مسح البيانات المحلية
      this.authToken = null;
      this.currentUser = null;
      this.saveToStorage();
      this.updateUI();

      ToastManager.success('تم تسجيل الخروج بنجاح');
      return true;
    } catch (error) {
      console.error('Logout error:', error);
      throw error;
    }
  },

  /**
   * حذف الحساب
   */
  async deleteAccount() {
    try {
      if (!this.authToken) {
        throw new Error('لم يتم تسجيل الدخول');
      }

      const response = await fetch(`${this.apiBaseUrl}/api/users/delete`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${this.authToken}`,
          'Content-Type': 'application/json'
        }
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'فشل حذف الحساب');
      }

      // مسح البيانات المحلية
      this.authToken = null;
      this.currentUser = null;
      this.saveToStorage();
      this.updateUI();

      ToastManager.success('تم حذف الحساب بنجاح');
      return true;
    } catch (error) {
      console.error('Delete account error:', error);
      throw error;
    }
  },

  /**
   * تحديث بيانات الملف الشخصي
   * @param {object} updates - البيانات المراد تحديثها
   */
  async updateProfile(updates) {
    try {
      if (!this.authToken) {
        throw new Error('لم يتم تسجيل الدخول');
      }

      const response = await fetch(`${this.apiBaseUrl}/api/users/profile`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${this.authToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(updates)
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'فشل تحديث الملف الشخصي');
      }

      // تحديث البيانات المحلية
      this.currentUser = data.data.user;
      this.saveToStorage();
      this.updateUI();

      ToastManager.success('تم تحديث الملف الشخصي بنجاح');
      return data.data.user;
    } catch (error) {
      console.error('Update profile error:', error);
      throw error;
    }
  },

  /**
   * تحميل صورة البروفايل
   * @param {File} file - ملف الصورة
   */
  async uploadAvatar(file) {
    try {
      if (!this.authToken) {
        throw new Error('لم يتم تسجيل الدخول');
      }

      const formData = new FormData();
      formData.append('avatar', file);

      const response = await fetch(`${this.apiBaseUrl}/api/users/avatar`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.authToken}`
        },
        body: formData
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'فشل تحميل الصورة');
      }

      // تحديث البيانات المحلية
      this.currentUser = data.data.user;
      this.saveToStorage();
      this.updateUI();

      ToastManager.success('تم تحديث صورة البروفايل بنجاح');
      return data.data.user;
    } catch (error) {
      console.error('Avatar upload error:', error);
      throw error;
    }
  },

  /**
   * تحديث واجهة المستخدم بناءً على حالة المصادقة
   */
  updateUI() {
    const isAuthenticated = this.isAuthenticated();

    // تحديث العناصر المعتمدة على حالة المصادقة
    const authElements = document.querySelectorAll('[data-auth-required]');
    authElements.forEach(el => {
      if (isAuthenticated) {
        el.style.display = '';
        el.classList.remove('hidden');
      } else {
        el.style.display = 'none';
        el.classList.add('hidden');
      }
    });

    // تحديث العناصر المخفية للمستخدمين المسجلين
    const notAuthElements = document.querySelectorAll('[data-not-auth]');
    notAuthElements.forEach(el => {
      if (!isAuthenticated) {
        el.style.display = '';
        el.classList.remove('hidden');
      } else {
        el.style.display = 'none';
        el.classList.add('hidden');
      }
    });

    // تحديث بيانات المستخدم في الواجهة
    if (isAuthenticated && this.currentUser) {
      const userNameElements = document.querySelectorAll('[data-user-name]');
      userNameElements.forEach(el => {
        el.textContent = this.currentUser.full_name || this.currentUser.username;
      });

      const userAvatarElements = document.querySelectorAll('[data-user-avatar]');
      userAvatarElements.forEach(el => {
        if (this.currentUser.avatar) {
          el.src = this.currentUser.avatar;
        }
      });
    }

    // تشغيل حدث مخصص للواجهات الأخرى
    window.dispatchEvent(new CustomEvent('userStateChanged', {
      detail: {
        isAuthenticated: isAuthenticated,
        user: this.currentUser
      }
    }));
  },

  /**
   * الحصول على المستخدم الحالي
   * @returns {object|null} بيانات المستخدم الحالي
   */
  getCurrentUser() {
    return this.currentUser;
  },

  /**
   * الحصول على التوكن الحالي
   * @returns {string|null} التوكن الحالي
   */
  getToken() {
    return this.authToken;
  }
};

// ================================================================
// 3. App - إدارة التطبيق والحماية
// ================================================================

const App = {
  /**
   * قائمة الصفحات العامة (متاحة بدون تسجيل دخول)
   */
  publicPages: [
    'index.html',
    'olympiad.html',
    'grade9.html',
    'outstanding.html',
    'random-quiz.html',
    'team.html',
    'team-olympiad.html',
    'team-grade9.html',
    'team-outstanding.html',
    'initiative.html',
    'login.html',
    'signup.html',
    'search.html',
    'leaderboard.html'
  ],

  /**
   * قائمة الصفحات المحمية (تتطلب تسجيل دخول)
   */
  protectedPages: [
    'quiz.html',
    'dashboard.html',
    'community.html',
    'profile.html'
  ],

  /**
   * تهيئة التطبيق
   */
  init() {
    // تهيئة مدير المستخدمين
    UserManager.init();

    // التحقق من المصادقة وحماية الصفحات
    this.checkAuth();

    // ربط الأحداث العامة
    this.attachEventListeners();
  },

  /**
   * الحصول على اسم الصفحة الحالية من URL
   * @returns {string} اسم الملف الحالي (مثل: index.html)
   */
  getCurrentPageName() {
    const path = window.location.pathname;
    const filename = path.substring(path.lastIndexOf('/') + 1) || 'index.html';
    return filename;
  },

  /**
   * التحقق من أن الصفحة الحالية عامة
   * @returns {boolean} true إذا كانت الصفحة عامة
   */
  isPublicPage() {
    const pageName = this.getCurrentPageName();
    return this.publicPages.some(page => pageName === page || pageName.includes(page));
  },

  /**
   * التحقق من أن الصفحة الحالية محمية
   * @returns {boolean} true إذا كانت الصفحة محمية
   */
  isProtectedPage() {
    const pageName = this.getCurrentPageName();
    return this.protectedPages.some(page => pageName === page || pageName.includes(page));
  },

  /**
   * التحقق من المصادقة وحماية الصفحات
   * لا يتم الاتصال بالخادم - نعتمد فقط على localStorage
   */
  checkAuth() {
    const isAuthenticated = UserManager.isAuthenticated();
    const pageName = this.getCurrentPageName();

    // إذا كانت الصفحة محمية والمستخدم غير مسجل
    if (this.isProtectedPage() && !isAuthenticated) {
      console.warn(`Protected page '${pageName}' accessed without authentication. Redirecting to login.`);
      window.location.href = 'login.html';
      return;
    }

    // إذا كانت الصفحة عامة، السماح بالوصول
    if (this.isPublicPage()) {
      return;
    }

    // صفحة غير معروفة - السماح بالوصول (يمكن تعديل هذا حسب الحاجة)
    console.info(`Unknown page '${pageName}' - allowing access`);
  },

  /**
   * ربط الأحداث العامة
   */
  attachEventListeners() {
    // الاستماع لحدث تغيير حالة المستخدم
    window.addEventListener('userStateChanged', (event) => {
      console.log('User state changed:', event.detail);
      // يمكن تنفيذ إجراءات إضافية هنا
    });

    // السماح للصفحات بربط معالجات تسجيل الدخول والخروج
    this.setupAuthForms();
  },

  /**
   * إعداد نماذج المصادقة (تسجيل الدخول والتسجيل)
   */
  setupAuthForms() {
    // نموذج تسجيل الدخول
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username')?.value;
        const password = document.getElementById('password')?.value;

        if (!username || !password) {
          ToastManager.error('يرجى ملء جميع الحقول');
          return;
        }

        try {
          await UserManager.login(username, password);
          // إعادة التوجيه إلى الصفحة الرئيسية بعد تسجيل الدخول
          setTimeout(() => {
            window.location.href = 'index.html';
          }, 500);
        } catch (error) {
          ToastManager.error(error.message || 'فشل تسجيل الدخول');
        }
      });
    }

    // نموذج التسجيل
    const signupForm = document.getElementById('signup-form');
    if (signupForm) {
      signupForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const username = document.getElementById('signup-username')?.value;
        const email = document.getElementById('signup-email')?.value;
        const full_name = document.getElementById('signup-fullname')?.value;
        const password = document.getElementById('signup-password')?.value;
        const confirmPassword = document.getElementById('signup-confirmPassword')?.value;

        if (!username || !email || !full_name || !password || !confirmPassword) {
          ToastManager.error('يرجى ملء جميع الحقول');
          return;
        }

        if (password !== confirmPassword) {
          ToastManager.error('كلمات المرور غير متطابقة');
          return;
        }

        try {
          await UserManager.signup({
            username,
            email,
            full_name,
            password,
            age: document.getElementById('signup-age')?.value || null,
            governorate: document.getElementById('signup-governorate')?.value || null,
            school: document.getElementById('signup-school')?.value || null
          });

          setTimeout(() => {
            window.location.href = 'index.html';
          }, 500);
        } catch (error) {
          ToastManager.error(error.message || 'فشل إنشاء الحساب');
        }
      });
    }

    // زر تسجيل الخروج
    const logoutButtons = document.querySelectorAll('[data-logout-btn]');
    logoutButtons.forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.preventDefault();
        try {
          await UserManager.logout();
          setTimeout(() => {
            window.location.href = 'login.html';
          }, 500);
        } catch (error) {
          ToastManager.error('فشل تسجيل الخروج');
        }
      });
    });

    // زر حذف الحساب
    const deleteAccountButtons = document.querySelectorAll('[data-delete-account-btn]');
    deleteAccountButtons.forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.preventDefault();
        if (!confirm('هل أنت متأكد من رغبتك في حذف حسابك؟ هذا الإجراء لا يمكن التراجع عنه.')) {
          return;
        }
        try {
          await UserManager.deleteAccount();
          setTimeout(() => {
            window.location.href = 'login.html';
          }, 500);
        } catch (error) {
          ToastManager.error(error.message || 'فشل حذف الحساب');
        }
      });
    });
  },

  /**
   * إعادة التوجيه إلى صفحة معينة
   * @param {string} page - اسم الصفحة
   */
  navigateTo(page) {
    window.location.href = page;
  },

  /**
   * التحقق من أن المستخدم الحالي هو مشرف
   * @returns {boolean} true إذا كان المستخدم مشرفاً
   */
  isAdmin() {
    const user = UserManager.getCurrentUser();
    return user && user.is_admin === true;
  }
};

// ================================================================
// 4. تهيئة التطبيق عند تحميل الصفحة
// ================================================================

// التحقق من أن المستند قد تم تحميله
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    App.init();
  });
} else {
  // المستند تم تحميله بالفعل
  App.init();
}

// ================================================================
// 5. تصدير للاستخدام في ملفات أخرى (اختياري)
// ================================================================

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { App, UserManager, ToastManager };
}
