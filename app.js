// Service card popup functionality
const popup = document.getElementById('popup');
const popupTitle = document.getElementById('popup-title');
const popupText = document.getElementById('popup-text');
const closeBtn = document.querySelector('#popup .close-btn');

const popupData = {
  'Pronto Chat API Integration': "We believe that communications should be reliable, secure, and an enjoyable experience. Pronto is one of the most popular communication systems used within schools and companies. But it lacks important features and security that are needed towards keeping users happy while chatting. That is where we step in. We at SafeComms Incorporated Produce extensions on Pronto that bring the fun back in texting. To follow our progress on any product or get updates, please sign up. Thank you! ",
  'Mod Bot Beta 1': "Hostility on chat is very easy. Cat-fishing, harassment, and many more illegal and inappropriate activties occur throughout communications. Human mods can monitor chats, but can also easily be persuaded to ignore complaints and maybe even support such content. That is where the Mod Bot Beta 1 comes in. The Mod Bot was designed to monitor all activity in a chat. The facts are that we believe in safety and a hostile-free work environment for all users. To follow our progress on any product or get updates, please sign up. Thank you!",
  'Custom GUIs': "Our GUIs are designed to create a user interface that brings reliability, quality, and technology all in one. While making it easy to use, we integrate hundreds of features that not only make communication simple, but bring enjoyment and productivity to communication as well. To follow our progress on any product or get updates, please sign up. Thank you!",
  'API': "SafeComms Incorporated has a close relationship with the Pronto API. However, we are not solely based on making products and GUIs that run on it. Currently, we are in the process of introducing a new GUI from DACMO-Works called BroPro. However, we aren't stopping there. We will soon begin work on our very own API. To follow our progress on any product or get updates, please sign up. Thank you!"
};

document.querySelectorAll('.service-card').forEach(card => {
  card.addEventListener('click', () => {
    const title = card.querySelector('h3').innerText;
    popupTitle.innerText = title;
    popupText.innerText = popupData[title] || "More details coming soon.";
    popup.style.display = 'flex';
  });
});

closeBtn.addEventListener('click', () => {
  popup.style.display = 'none';
});

window.addEventListener('click', (e) => {
  if (e.target === popup) {
    popup.style.display = 'none';
  }
});

// Profile link handler (placeholder for future implementation)
document.getElementById('profile-link').addEventListener('click', (e) => {
  e.preventDefault();
  alert('Profile page coming soon!');
});

// Settings link handler (placeholder for future implementation)
document.getElementById('settings-link').addEventListener('click', (e) => {
  e.preventDefault();
  alert('Settings page coming soon!');
});

// Resend verification email
document.querySelector('.verification-status').addEventListener('click', () => {
  const user = firebase.auth().currentUser;
  if (user && !user.emailVerified) {
    user.sendEmailVerification()
      .then(() => {
        alert('Verification email sent. Please check your inbox.');
      })
      .catch((error) => {
        alert('Error sending verification email: ' + error.message);
      });
  }
});
