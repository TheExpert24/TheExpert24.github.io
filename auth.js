// Firebase configuration and authentication
const firebaseConfig = {
  apiKey: "AIzaSyA90B4IFvedjMlctwuV0mKTocrkx-6ErD4",
  authDomain: "safecomms-incorporated.firebaseapp.com",
  projectId: "safecomms-incorporated",
  storageBucket: "safecomms-incorporated.appspot.com",
  messagingSenderId: "1035230396120",
  appId: "1:1035230396120:web:fbc23f2258ab41a556e1ad",
  measurementId: "G-6WZK36D0VX"
};

// Initialize Firebase
firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();

// DOM Elements
const signupBtn = document.getElementById('signup-btn');
const userAccount = document.getElementById('user-account');
const userInitial = document.querySelector('.user-initial');
const userEmail = document.querySelector('.user-email');
const verificationStatus = document.querySelector('.verification-status');
const logoutBtn = document.getElementById('logout-btn');

// Auth Modals
const signupModal = document.getElementById('signup-modal');
const loginModal = document.getElementById('login-modal');
const forgotPasswordModal = document.getElementById('forgot-password-modal');

// Modal Close Buttons
const signupClose = document.getElementById('signup-close');
const loginClose = document.getElementById('login-close');
const forgotPasswordClose = document.getElementById('forgot-password-close');

// Auth Forms
const signupForm = document.getElementById('signup-form');
const loginForm = document.getElementById('login-form');
const forgotPasswordForm = document.getElementById('forgot-password-form');

// Auth Navigation Links
const switchToSignup = document.getElementById('switch-to-signup');
const forgotPasswordLink = document.getElementById('forgot-password-link');
const backToLogin = document.getElementById('back-to-login');

// Check Auth State on Load
document.addEventListener('DOMContentLoaded', () => {
  auth.onAuthStateChanged(user => {
    updateUIBasedOnAuthState(user);
  });
});

// Update UI based on authentication state
function updateUIBasedOnAuthState(user) {
  if (user) {
    // User is signed in
    signupBtn.style.display = 'none';
    userAccount.style.display = 'block';
    
    // Update user info
    const email = user.email;
    userEmail.textContent = email;
    
    // Set user initial (first letter of email)
    userInitial.textContent = email.charAt(0).toUpperCase();
    
    // Check email verification status
    if (user.emailVerified) {
      verificationStatus.textContent = 'Verified';
      verificationStatus.classList.add('verified');
      verificationStatus.classList.remove('unverified');
      document.querySelector('.user-avatar').classList.add('verified');
    } else {
      verificationStatus.textContent = 'Unverified';
      verificationStatus.classList.add('unverified');
      verificationStatus.classList.remove('verified');
      document.querySelector('.user-avatar').classList.remove('verified');
    }
  } else {
    // User is signed out
    signupBtn.style.display = 'block';
    userAccount.style.display = 'none';
  }
}

// Event Listeners for Auth UI
signupBtn.addEventListener('click', (e) => {
  e.preventDefault();
  // Check if user is logged in
  const user = auth.currentUser;
  if (user) {
    // If logged in, toggle dropdown visibility
    userAccount.classList.toggle('show-dropdown');
  } else {
    // If not logged in, show login modal instead of signup
    loginModal.style.display = 'flex';
  }
});

// Modal close handlers
signupClose.addEventListener('click', () => {
  signupModal.style.display = 'none';
});

loginClose.addEventListener('click', () => {
  loginModal.style.display = 'none';
});

forgotPasswordClose.addEventListener('click', () => {
  forgotPasswordModal.style.display = 'none';
});

// Close modals when clicking outside
window.addEventListener('click', (e) => {
  if (e.target === signupModal) {
    signupModal.style.display = 'none';
  }
  if (e.target === loginModal) {
    loginModal.style.display = 'none';
  }
  if (e.target === forgotPasswordModal) {
    forgotPasswordModal.style.display = 'none';
  }
});

// Switch between auth modals
switchToSignup.addEventListener('click', (e) => {
  e.preventDefault();
  loginModal.style.display = 'none';
  signupModal.style.display = 'flex';
});

forgotPasswordLink.addEventListener('click', (e) => {
  e.preventDefault();
  loginModal.style.display = 'none';
  forgotPasswordModal.style.display = 'flex';
});

backToLogin.addEventListener('click', (e) => {
  e.preventDefault();
  forgotPasswordModal.style.display = 'none';
  loginModal.style.display = 'flex';
});

// Handle signup form submission
signupForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const email = document.getElementById('signup-email').value;
  const password = document.getElementById('signup-password').value;

  auth.createUserWithEmailAndPassword(email, password)
    .then((userCredential) => {
      const user = userCredential.user;

      // Send email verification
      user.sendEmailVerification()
        .then(() => {
          alert("Sign-up successful. Please check your email to verify your account.");
          signupModal.style.display = 'none';
          updateUIBasedOnAuthState(user);
        })
        .catch((error) => {
          alert("Error sending verification email: " + error.message);
        });
    })
    .catch((error) => {
      alert("Error: " + error.message);
    });
});

// Handle login form submission
loginForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const email = document.getElementById('login-email').value;
  const password = document.getElementById('login-password').value;

  auth.signInWithEmailAndPassword(email, password)
    .then((userCredential) => {
      const user = userCredential.user;
      loginModal.style.display = 'none';
      updateUIBasedOnAuthState(user);
    })
    .catch((error) => {
      alert("Error: " + error.message);
    });
});

// Handle forgot password form submission
forgotPasswordForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const email = document.getElementById('reset-email').value;

  auth.sendPasswordResetEmail(email)
    .then(() => {
      alert("Password reset email sent. Please check your inbox.");
      forgotPasswordModal.style.display = 'none';
      loginModal.style.display = 'flex';
    })
    .catch((error) => {
      alert("Error: " + error.message);
    });
});

// Handle logout
logoutBtn.addEventListener('click', (e) => {
  e.preventDefault();
  auth.signOut()
    .then(() => {
      updateUIBasedOnAuthState(null);
    })
    .catch((error) => {
      alert("Error signing out: " + error.message);
    });
});
