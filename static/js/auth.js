/**
 * TruthLens Authentication & Landing Controller
 * Handles user login, registration, session management, and redirection.
 */

(function () {
  'use strict';

  // Modal elements
  const loginModal = document.getElementById("loginModal");
  const signupModal = document.getElementById("signupModal");

  const openLoginBtn = document.getElementById("openLogin");
  const openSignupBtn = document.getElementById("openSignup");
  const getStartedBtn = document.getElementById("getStarted");

  const closeLoginBtn = document.getElementById("closeLogin");
  const closeSignupBtn = document.getElementById("closeSignup");

  const switchToSignup = document.getElementById("switchToSignup");
  const switchToLogin = document.getElementById("switchToLogin");

  // Form elements
  const loginForm = document.getElementById("loginForm");
  const signupForm = document.getElementById("signupForm");
  const loginMessage = document.getElementById("loginMessage");
  const signupMessage = document.getElementById("signupMessage");

  // Header auth elements
  const guestHeaderButtons = document.getElementById("guestHeaderButtons");
  const authUserBadge = document.getElementById("authUserBadge");
  const headerOfficerName = document.getElementById("headerOfficerName");
  const btnSignOut = document.getElementById("btnSignOut");

  function closeAllModals() {
    if (loginModal) loginModal.classList.remove("active");
    if (signupModal) signupModal.classList.remove("active");
    if (loginMessage) {
      loginMessage.className = "message";
      loginMessage.textContent = "";
    }
    if (signupMessage) {
      signupMessage.className = "message";
      signupMessage.textContent = "";
    }
  }

  function openLoginModal() {
    closeAllModals();
    if (loginModal) {
      loginModal.classList.add("active");
      const emailInput = document.getElementById("loginEmail");
      if (emailInput) setTimeout(() => emailInput.focus(), 100);
    }
  }

  function openSignupModal() {
    closeAllModals();
    if (signupModal) {
      signupModal.classList.add("active");
      const nameInput = document.getElementById("fullName");
      if (nameInput) setTimeout(() => nameInput.focus(), 100);
    }
  }

  let currentUser = null;

  function handleGetStarted(e) {
    if (e) e.preventDefault();
    const token = localStorage.getItem("truthlens_token");
    if (currentUser || token) {
      window.location.href = "/dashboard";
    } else {
      openLoginModal();
    }
  }
  window.handleGetStartedClick = handleGetStarted;

  // Bind Openers
  if (openLoginBtn) openLoginBtn.addEventListener("click", openLoginModal);
  if (openSignupBtn) openSignupBtn.addEventListener("click", openSignupModal);
  if (getStartedBtn) getStartedBtn.addEventListener("click", handleGetStarted);

  // Bind Closers
  if (closeLoginBtn) closeLoginBtn.addEventListener("click", closeAllModals);
  if (closeSignupBtn) closeSignupBtn.addEventListener("click", closeAllModals);

  // Switch between Login and Signup
  if (switchToSignup) {
    switchToSignup.addEventListener("click", function (e) {
      e.preventDefault();
      openSignupModal();
    });
  }

  if (switchToLogin) {
    switchToLogin.addEventListener("click", function (e) {
      e.preventDefault();
      openLoginModal();
    });
  }

  // Close modals on clicking backdrop
  window.addEventListener("click", function (e) {
    if (e.target === loginModal || e.target === signupModal) {
      closeAllModals();
    }
  });

  // Close modals on Escape key
  window.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      closeAllModals();
    }
  });

  // Quick-fill demo credentials helper
  window.fillDemoCredentials = function (email, password) {
    const emailInput = document.getElementById("loginEmail");
    const passwordInput = document.getElementById("loginPassword");
    if (emailInput && passwordInput) {
      emailInput.value = email;
      passwordInput.value = password;
      openLoginModal();
    }
  };

  // Helper to get redirect target
  function getRedirectTarget() {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get("redirect") || "/dashboard";
  }

  // =========================================================================
  // 1. LOGIN SUBMISSION
  // =========================================================================
  if (loginForm) {
    loginForm.addEventListener("submit", async function (e) {
      e.preventDefault();

      const email = document.getElementById("loginEmail").value.trim();
      const password = document.getElementById("loginPassword").value;
      const submitBtn = document.getElementById("btnLoginSubmit");
      const originalText = submitBtn ? submitBtn.textContent : "Log In";

      if (!email || !password) {
        showLoginMessage("Please enter your email and password.", "error");
        return;
      }

      try {
        if (submitBtn) {
          submitBtn.disabled = true;
          submitBtn.textContent = "Authenticating...";
        }

        const res = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password })
        });

        const data = await res.json();

        if (!res.ok || !data.success) {
          showLoginMessage(data.detail || data.message || "Invalid credentials. Please try again.", "error");
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
          }
          return;
        }

        // Store token in localStorage as backup
        if (data.token) {
          localStorage.setItem("truthlens_token", data.token);
          localStorage.setItem("truthlens_user", JSON.stringify(data.user || {}));
        }

        showLoginMessage("Login verified! Redirecting to Dashboard...", "success");

        setTimeout(() => {
          window.location.href = getRedirectTarget();
        }, 600);

      } catch (err) {
        showLoginMessage("Network error connecting to server. Please try again.", "error");
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = originalText;
        }
      }
    });
  }

  function showLoginMessage(text, type) {
    if (!loginMessage) return;
    loginMessage.textContent = text;
    loginMessage.className = "message " + type;
  }

  // =========================================================================
  // 2. SIGN UP SUBMISSION
  // =========================================================================
  if (signupForm) {
    signupForm.addEventListener("submit", async function (e) {
      e.preventDefault();

      const fullName = document.getElementById("fullName").value.trim();
      const email = document.getElementById("signupEmail").value.trim();
      const phone = document.getElementById("phone") ? document.getElementById("phone").value.trim() : "";
      const gender = document.getElementById("gender") ? document.getElementById("gender").value : "";
      const password = document.getElementById("signupPassword").value;
      const confirmPassword = document.getElementById("confirmPassword").value;
      const submitBtn = document.getElementById("btnSignupSubmit");
      const originalText = submitBtn ? submitBtn.textContent : "Sign Up";

      if (password !== confirmPassword) {
        showSignupMessage("Password and Confirm Password do not match.", "error");
        return;
      }

      if (password.length < 6) {
        showSignupMessage("Password must be at least 6 characters long.", "error");
        return;
      }

      try {
        if (submitBtn) {
          submitBtn.disabled = true;
          submitBtn.textContent = "Creating Account...";
        }

        const res = await fetch("/api/auth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            full_name: fullName,
            email,
            phone,
            gender,
            password,
            confirm_password: confirmPassword
          })
        });

        const data = await res.json();

        if (!res.ok || !data.success) {
          showSignupMessage(data.detail || data.message || "Failed to create account.", "error");
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
          }
          return;
        }

        if (data.token) {
          localStorage.setItem("truthlens_token", data.token);
          localStorage.setItem("truthlens_user", JSON.stringify(data.user || {}));
        }

        showSignupMessage("Account created successfully! Redirecting to Dashboard...", "success");

        setTimeout(() => {
          window.location.href = getRedirectTarget();
        }, 700);

      } catch (err) {
        showSignupMessage("Network error creating account. Please try again.", "error");
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = originalText;
        }
      }
    });
  }

  function showSignupMessage(text, type) {
    if (!signupMessage) return;
    signupMessage.textContent = text;
    signupMessage.className = "message " + type;
  }

  // =========================================================================
  // 3. LOGOUT HANDLER
  // =========================================================================
  if (btnSignOut) {
    btnSignOut.addEventListener("click", async function (e) {
      e.preventDefault();
      try {
        await fetch("/api/auth/logout", { method: "POST" });
      } catch (e) {}
      localStorage.removeItem("truthlens_token");
      localStorage.removeItem("truthlens_user");
      window.location.href = "/";
    });
  }

  // =========================================================================
  // 4. CHECK ACTIVE SESSION ON LOAD
  // =========================================================================
  async function checkActiveSession() {
    try {
      const res = await fetch("/api/auth/me");
      const data = await res.json();

      if (data.authenticated && data.user) {
        currentUser = data.user;

        // If user explicitly navigated to /login while authenticated, redirect to /dashboard
        if (window.location.pathname === "/login") {
          window.location.href = getRedirectTarget();
          return;
        }

        // Update header for logged in user
        if (guestHeaderButtons) guestHeaderButtons.style.display = "none";
        if (authUserBadge) {
          authUserBadge.classList.add("active");
          if (headerOfficerName) {
            headerOfficerName.textContent = data.user.full_name || "Officer";
          }
        }

        // Ensure button displays 'Get Started' to launch website
        if (getStartedBtn) {
          const span = getStartedBtn.querySelector("span");
          if (span) span.textContent = "Get Started";
          getStartedBtn.setAttribute("title", "Get Started — Launch TruthLens Website");
        }
      } else {
        currentUser = null;
        if (getStartedBtn) {
          const span = getStartedBtn.querySelector("span");
          if (span) span.textContent = "Get Started";
          getStartedBtn.setAttribute("title", "Get Started with TruthLens");
        }
        // Check URL path or query params to auto-open modal
        if (window.location.pathname === "/login" || window.location.hash === "#login") {
          openLoginModal();
        } else if (window.location.hash === "#signup") {
          openSignupModal();
        }
      }
    } catch (e) {
      console.warn("Session check error:", e);
    }
  }

  // Initialize on load
  checkActiveSession();

})();
