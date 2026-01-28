// State
let currentUser = null;

// DOM elements
const authScreen = document.getElementById('auth-screen');
const mainScreen = document.getElementById('main-screen');
const loginForm = document.getElementById('login-form');
const signupForm = document.getElementById('signup-form');
const authError = document.getElementById('auth-error');

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  await checkAuth();
  await checkOAuthProviders();
  setupEventListeners();
  checkForOAuthError();
});

// Check if OAuth providers are available
async function checkOAuthProviders() {
  try {
    const res = await fetch('/api/auth/providers');
    const providers = await res.json();
    
    if (providers.google) {
      document.getElementById('google-signin-btn').classList.remove('hidden');
      document.getElementById('google-signup-btn').classList.remove('hidden');
      document.getElementById('oauth-divider').classList.remove('hidden');
      document.getElementById('oauth-divider-signup').classList.remove('hidden');
    }
  } catch (err) {
    console.log('OAuth providers check failed');
  }
}

// Check for OAuth errors in URL
function checkForOAuthError() {
  const params = new URLSearchParams(window.location.search);
  if (params.get('error') === 'oauth_failed') {
    authError.textContent = 'Google sign-in failed. Please try again.';
    // Clean up URL
    window.history.replaceState({}, document.title, window.location.pathname);
  }
}

async function checkAuth() {
  try {
    const res = await fetch('/api/me');
    if (res.ok) {
      const data = await res.json();
      currentUser = data.user;
      showMainScreen(data);
    }
  } catch (err) {
    console.log('Not logged in');
  }
}

function setupEventListeners() {
  // Auth tabs
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      
      if (btn.dataset.tab === 'login') {
        loginForm.classList.remove('hidden');
        signupForm.classList.add('hidden');
      } else {
        loginForm.classList.add('hidden');
        signupForm.classList.remove('hidden');
      }
    });
  });

  // Login
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(loginForm);
    await login(formData.get('email'), formData.get('password'));
  });

  // Signup
  signupForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(signupForm);
    await signup(formData.get('name'), formData.get('email'), formData.get('password'));
  });

  // Logout
  document.getElementById('logout-btn').addEventListener('click', logout);

  // Navigation tabs
  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
      
      tab.classList.add('active');
      document.getElementById(`${tab.dataset.view}-view`).classList.remove('hidden');
      
      // Load data for the view
      if (tab.dataset.view === 'browse') loadBabysitters();
      if (tab.dataset.view === 'connections') loadConnections();
    });
  });

  // Add connection form
  document.getElementById('add-connection-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    await addConnection(formData.get('email'), formData.get('relationship_type'));
    e.target.reset();
  });

  // Babysitter profile form
  document.getElementById('babysitter-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    await saveBabysitterProfile({
      bio: formData.get('bio'),
      experience: formData.get('experience'),
      certifications: formData.get('certifications'),
      hourly_rate: formData.get('hourly_rate'),
      age_range: formData.get('age_range'),
      availability: formData.get('availability')
    });
  });

  // Sitter search for vouching
  const sitterSearch = document.getElementById('sitter-search');
  let searchTimeout;
  sitterSearch.addEventListener('input', () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => searchSitters(sitterSearch.value), 300);
  });

  // Vouch form
  document.getElementById('vouch-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    await submitVouch({
      babysitter_id: formData.get('babysitter_id'),
      relationship: formData.get('relationship'),
      times_used: formData.get('times_used'),
      recommendation: formData.get('recommendation')
    });
  });

  // Modal close
  document.querySelector('.modal-close').addEventListener('click', closeModal);
  document.getElementById('sitter-modal').addEventListener('click', (e) => {
    if (e.target.id === 'sitter-modal') closeModal();
  });
}

// Auth functions
async function login(email, password) {
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();
    
    if (!res.ok) {
      authError.textContent = data.error;
      return;
    }
    
    currentUser = data.user;
    await checkAuth();
  } catch (err) {
    authError.textContent = 'Login failed';
  }
}

async function signup(name, email, password) {
  try {
    const res = await fetch('/api/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, password })
    });
    const data = await res.json();
    
    if (!res.ok) {
      authError.textContent = data.error;
      return;
    }
    
    await checkAuth();
  } catch (err) {
    authError.textContent = 'Signup failed';
  }
}

async function logout() {
  await fetch('/api/logout', { method: 'POST' });
  currentUser = null;
  authScreen.classList.remove('hidden');
  mainScreen.classList.add('hidden');
  loginForm.reset();
  signupForm.reset();
}

function showMainScreen(data) {
  authScreen.classList.add('hidden');
  mainScreen.classList.remove('hidden');
  document.getElementById('user-name').textContent = data.user.name;
  
  // Pre-fill babysitter form if profile exists
  if (data.profile) {
    const form = document.getElementById('babysitter-form');
    form.bio.value = data.profile.bio || '';
    form.experience.value = data.profile.experience || '';
    form.certifications.value = data.profile.certifications || '';
    form.hourly_rate.value = data.profile.hourly_rate || '';
    form.age_range.value = data.profile.age_range || '';
    form.availability.value = data.profile.availability || '';
  }
  
  loadBabysitters();
}

// Babysitter functions
async function loadBabysitters() {
  const container = document.getElementById('babysitters-list');
  
  try {
    const res = await fetch('/api/babysitters');
    const sitters = await res.json();
    
    if (sitters.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <span class="empty-icon">🔗</span>
          <p>No babysitters found in your network yet.</p>
          <p class="hint">Connect with friends to see their recommendations!</p>
        </div>
      `;
      return;
    }
    
    container.innerHTML = sitters.map(sitter => `
      <div class="sitter-card" onclick="showSitterDetail(${sitter.id})">
        <div class="sitter-header">
          <div class="sitter-avatar">${sitter.name.charAt(0).toUpperCase()}</div>
          <div>
            <div class="sitter-name">${escapeHtml(sitter.name)}</div>
            ${sitter.hourly_rate ? `<div class="sitter-rate">$${sitter.hourly_rate}/hr</div>` : ''}
          </div>
        </div>
        
        <span class="trust-badge degree-${sitter.closestConnection}">
          ${sitter.closestConnection === 1 ? '🤝 1st Degree' : '🔗 2nd Degree'}
        </span>
        
        ${sitter.trustChains && sitter.trustChains[0] ? `
          <div class="trust-chain">
            ${escapeHtml(sitter.trustChains[0].path)}
          </div>
        ` : ''}
        
        <div class="vouch-count">👍 ${sitter.vouchCount} vouch${sitter.vouchCount === 1 ? '' : 'es'}</div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load babysitters', err);
  }
}

async function showSitterDetail(id) {
  try {
    const res = await fetch(`/api/babysitters/${id}`);
    const sitter = await res.json();
    
    const detail = document.getElementById('sitter-detail');
    detail.innerHTML = `
      <div class="detail-header">
        <div class="detail-avatar">${sitter.name.charAt(0).toUpperCase()}</div>
        <div>
          <div class="detail-name">${escapeHtml(sitter.name)}</div>
          ${sitter.hourly_rate ? `<div class="sitter-rate">$${sitter.hourly_rate}/hr</div>` : ''}
        </div>
      </div>
      
      ${sitter.bio ? `
        <div class="detail-section">
          <h4>About</h4>
          <p>${escapeHtml(sitter.bio)}</p>
        </div>
      ` : ''}
      
      ${sitter.experience ? `
        <div class="detail-section">
          <h4>Experience</h4>
          <p>${escapeHtml(sitter.experience)}</p>
        </div>
      ` : ''}
      
      ${sitter.certifications ? `
        <div class="detail-section">
          <h4>Certifications</h4>
          <p>${escapeHtml(sitter.certifications)}</p>
        </div>
      ` : ''}
      
      ${sitter.age_range ? `
        <div class="detail-section">
          <h4>Age Range</h4>
          <p>${escapeHtml(sitter.age_range)}</p>
        </div>
      ` : ''}
      
      ${sitter.availability ? `
        <div class="detail-section">
          <h4>Availability</h4>
          <p>${escapeHtml(sitter.availability)}</p>
        </div>
      ` : ''}
      
      <div class="detail-section">
        <h4>Vouches (${sitter.vouches.length})</h4>
        ${sitter.vouches.map(v => `
          <div class="vouch-item">
            <div class="vouch-header">
              <span class="vouch-name">${escapeHtml(v.voucher_name)}</span>
              <span class="vouch-times">Used ${v.times_used}x</span>
            </div>
            ${v.relationship ? `<div class="vouch-text"><em>${escapeHtml(v.relationship)}</em></div>` : ''}
            ${v.recommendation ? `<div class="vouch-text">"${escapeHtml(v.recommendation)}"</div>` : ''}
          </div>
        `).join('')}
      </div>
    `;
    
    document.getElementById('sitter-modal').classList.remove('hidden');
  } catch (err) {
    console.error('Failed to load sitter detail', err);
  }
}

function closeModal() {
  document.getElementById('sitter-modal').classList.add('hidden');
}

// Connection functions
async function loadConnections() {
  // Load pending requests
  try {
    const requestsRes = await fetch('/api/connection-requests');
    const requests = await requestsRes.json();
    
    const requestsContainer = document.getElementById('pending-requests');
    if (requests.length === 0) {
      requestsContainer.innerHTML = '<p class="hint">No pending requests</p>';
    } else {
      requestsContainer.innerHTML = requests.map(req => `
        <div class="request-item">
          <div class="connection-info">
            <div class="connection-avatar">${req.name.charAt(0).toUpperCase()}</div>
            <div>
              <div class="connection-name">${escapeHtml(req.name)}</div>
              <div class="connection-type">${escapeHtml(req.email)}</div>
            </div>
          </div>
          <button class="btn btn-accept" onclick="acceptConnection(${req.id})">Accept</button>
        </div>
      `).join('');
    }
  } catch (err) {
    console.error('Failed to load requests', err);
  }
  
  // Load connections
  try {
    const connectionsRes = await fetch('/api/connections');
    const connections = await connectionsRes.json();
    
    const connectionsContainer = document.getElementById('connections-list');
    if (connections.length === 0) {
      connectionsContainer.innerHTML = '<p class="hint">No connections yet. Add friends by email!</p>';
    } else {
      connectionsContainer.innerHTML = connections.map(conn => `
        <div class="connection-item">
          <div class="connection-info">
            <div class="connection-avatar">${conn.friend.name.charAt(0).toUpperCase()}</div>
            <div>
              <div class="connection-name">${escapeHtml(conn.friend.name)}</div>
              <div class="connection-type">${escapeHtml(conn.relationship_type)}</div>
            </div>
          </div>
        </div>
      `).join('');
    }
  } catch (err) {
    console.error('Failed to load connections', err);
  }
}

async function addConnection(email, relationshipType) {
  const msgEl = document.getElementById('connection-message');
  try {
    const res = await fetch('/api/connections', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, relationship_type: relationshipType })
    });
    const data = await res.json();
    
    if (!res.ok) {
      msgEl.textContent = data.error;
      msgEl.className = 'message error';
      return;
    }
    
    msgEl.textContent = 'Connection request sent!';
    msgEl.className = 'message success';
    setTimeout(() => { msgEl.textContent = ''; }, 3000);
  } catch (err) {
    msgEl.textContent = 'Failed to send request';
    msgEl.className = 'message error';
  }
}

async function acceptConnection(id) {
  try {
    await fetch(`/api/connections/${id}/accept`, { method: 'POST' });
    loadConnections();
  } catch (err) {
    console.error('Failed to accept connection', err);
  }
}

// Profile functions
async function saveBabysitterProfile(profile) {
  const msgEl = document.getElementById('profile-message');
  try {
    const res = await fetch('/api/babysitter-profile', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(profile)
    });
    
    if (!res.ok) {
      const data = await res.json();
      msgEl.textContent = data.error;
      msgEl.className = 'message error';
      return;
    }
    
    msgEl.textContent = 'Babysitter profile saved!';
    msgEl.className = 'message success';
    currentUser.is_babysitter = 1;
    setTimeout(() => { msgEl.textContent = ''; }, 3000);
  } catch (err) {
    msgEl.textContent = 'Failed to save profile';
    msgEl.className = 'message error';
  }
}

// Vouch functions
async function searchSitters(query) {
  const resultsEl = document.getElementById('sitter-results');
  
  if (!query || query.length < 2) {
    resultsEl.classList.remove('active');
    return;
  }
  
  try {
    const res = await fetch(`/api/users/search?q=${encodeURIComponent(query)}`);
    const users = await res.json();
    
    // Filter to babysitters only
    const sitters = users.filter(u => u.is_babysitter);
    
    if (sitters.length === 0) {
      resultsEl.innerHTML = '<div class="search-result-item">No babysitters found</div>';
    } else {
      resultsEl.innerHTML = sitters.map(s => `
        <div class="search-result-item" onclick="selectSitter(${s.id}, '${escapeHtml(s.name)}', '${escapeHtml(s.email)}')">
          <span>${escapeHtml(s.name)}</span>
          <span class="hint">${escapeHtml(s.email)}</span>
        </div>
      `).join('');
    }
    
    resultsEl.classList.add('active');
  } catch (err) {
    console.error('Search failed', err);
  }
}

function selectSitter(id, name, email) {
  document.getElementById('selected-sitter-id').value = id;
  document.getElementById('sitter-search').value = '';
  document.getElementById('sitter-results').classList.remove('active');
  
  const selectedEl = document.getElementById('selected-sitter');
  selectedEl.innerHTML = `
    <span>👤 ${escapeHtml(name)} (${escapeHtml(email)})</span>
    <button type="button" class="btn btn-small" onclick="clearSelectedSitter()">✕</button>
  `;
  selectedEl.classList.add('active');
}

function clearSelectedSitter() {
  document.getElementById('selected-sitter-id').value = '';
  document.getElementById('selected-sitter').classList.remove('active');
}

async function submitVouch(vouch) {
  const msgEl = document.getElementById('vouch-message');
  
  if (!vouch.babysitter_id) {
    msgEl.textContent = 'Please select a babysitter';
    msgEl.className = 'message error';
    return;
  }
  
  try {
    const res = await fetch('/api/vouch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(vouch)
    });
    
    if (!res.ok) {
      const data = await res.json();
      msgEl.textContent = data.error;
      msgEl.className = 'message error';
      return;
    }
    
    msgEl.textContent = 'Vouch submitted! Your network can now see this recommendation.';
    msgEl.className = 'message success';
    document.getElementById('vouch-form').reset();
    clearSelectedSitter();
    setTimeout(() => { msgEl.textContent = ''; }, 3000);
  } catch (err) {
    msgEl.textContent = 'Failed to submit vouch';
    msgEl.className = 'message error';
  }
}

// Utility
function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Expose functions to global scope for onclick handlers
window.showSitterDetail = showSitterDetail;
window.acceptConnection = acceptConnection;
window.selectSitter = selectSitter;
window.clearSelectedSitter = clearSelectedSitter;
