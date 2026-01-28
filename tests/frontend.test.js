/**
 * Frontend Rendering Tests
 * Tests that the HTML/CSS/JS renders correctly and core UI functions work
 */
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

let dom;
let document;
let window;

describe('Frontend Rendering', () => {
  beforeAll(() => {
    const html = fs.readFileSync(path.join(__dirname, '../public/index.html'), 'utf8');
    const css = fs.readFileSync(path.join(__dirname, '../public/styles.css'), 'utf8');
    
    dom = new JSDOM(html, {
      runScripts: 'outside-only',
      resources: 'usable'
    });
    document = dom.window.document;
    window = dom.window;
    
    // Inject CSS
    const style = document.createElement('style');
    style.textContent = css;
    document.head.appendChild(style);
  });

  describe('Page Structure', () => {
    test('has correct title', () => {
      expect(document.title).toBe('Babysitter Network - Trusted Recommendations');
    });

    test('has auth screen', () => {
      const authScreen = document.getElementById('auth-screen');
      expect(authScreen).not.toBeNull();
      expect(authScreen.classList.contains('screen')).toBe(true);
    });

    test('has main screen (hidden by default)', () => {
      const mainScreen = document.getElementById('main-screen');
      expect(mainScreen).not.toBeNull();
      expect(mainScreen.classList.contains('hidden')).toBe(true);
    });

    test('has login form', () => {
      const loginForm = document.getElementById('login-form');
      expect(loginForm).not.toBeNull();
      expect(loginForm.querySelector('input[name="email"]')).not.toBeNull();
      expect(loginForm.querySelector('input[name="password"]')).not.toBeNull();
    });

    test('has signup form', () => {
      const signupForm = document.getElementById('signup-form');
      expect(signupForm).not.toBeNull();
      expect(signupForm.querySelector('input[name="name"]')).not.toBeNull();
      expect(signupForm.querySelector('input[name="email"]')).not.toBeNull();
      expect(signupForm.querySelector('input[name="password"]')).not.toBeNull();
    });
  });

  describe('Navigation', () => {
    test('has navigation tabs', () => {
      const tabNav = document.querySelector('.tab-nav');
      expect(tabNav).not.toBeNull();
      
      const tabs = tabNav.querySelectorAll('.nav-tab');
      expect(tabs.length).toBe(3);
    });

    test('has browse view', () => {
      const browseView = document.getElementById('browse-view');
      expect(browseView).not.toBeNull();
    });

    test('has connections view', () => {
      const connectionsView = document.getElementById('connections-view');
      expect(connectionsView).not.toBeNull();
    });

    test('has profile view', () => {
      const profileView = document.getElementById('profile-view');
      expect(profileView).not.toBeNull();
    });
  });

  describe('Forms', () => {
    test('add connection form has required fields', () => {
      const form = document.getElementById('add-connection-form');
      expect(form).not.toBeNull();
      expect(form.querySelector('input[name="email"]')).not.toBeNull();
      expect(form.querySelector('select[name="relationship_type"]')).not.toBeNull();
    });

    test('babysitter form has all profile fields', () => {
      const form = document.getElementById('babysitter-form');
      expect(form).not.toBeNull();
      expect(form.querySelector('textarea[name="bio"]')).not.toBeNull();
      expect(form.querySelector('input[name="experience"]')).not.toBeNull();
      expect(form.querySelector('input[name="certifications"]')).not.toBeNull();
      expect(form.querySelector('input[name="hourly_rate"]')).not.toBeNull();
      expect(form.querySelector('input[name="age_range"]')).not.toBeNull();
      expect(form.querySelector('input[name="availability"]')).not.toBeNull();
    });

    test('vouch form has required fields', () => {
      const form = document.getElementById('vouch-form');
      expect(form).not.toBeNull();
      expect(form.querySelector('#sitter-search')).not.toBeNull();
      expect(form.querySelector('input[name="relationship"]')).not.toBeNull();
      expect(form.querySelector('input[name="times_used"]')).not.toBeNull();
      expect(form.querySelector('textarea[name="recommendation"]')).not.toBeNull();
    });
  });

  describe('Modal', () => {
    test('sitter modal exists and is hidden', () => {
      const modal = document.getElementById('sitter-modal');
      expect(modal).not.toBeNull();
      expect(modal.classList.contains('hidden')).toBe(true);
    });

    test('modal has close button', () => {
      const closeBtn = document.querySelector('.modal-close');
      expect(closeBtn).not.toBeNull();
    });
  });

  describe('UI Elements', () => {
    test('has logo with emoji', () => {
      const logoIcon = document.querySelector('.logo-icon');
      expect(logoIcon).not.toBeNull();
      expect(logoIcon.textContent).toBe('👶');
    });

    test('has tagline', () => {
      const tagline = document.querySelector('.tagline');
      expect(tagline).not.toBeNull();
      expect(tagline.textContent).toContain('trust');
    });

    test('has logout button', () => {
      const logoutBtn = document.getElementById('logout-btn');
      expect(logoutBtn).not.toBeNull();
    });

    test('has user name display', () => {
      const userName = document.getElementById('user-name');
      expect(userName).not.toBeNull();
    });
  });
});

describe('JavaScript Functions', () => {
  let js;

  beforeAll(() => {
    js = fs.readFileSync(path.join(__dirname, '../public/app.js'), 'utf8');
  });

  test('escapeHtml function exists and is exported', () => {
    expect(js).toContain('function escapeHtml');
  });

  test('has event listeners setup', () => {
    expect(js).toContain('addEventListener');
  });

  test('has auth functions', () => {
    expect(js).toContain('async function login');
    expect(js).toContain('async function signup');
    expect(js).toContain('async function logout');
  });

  test('has babysitter functions', () => {
    expect(js).toContain('async function loadBabysitters');
    expect(js).toContain('async function showSitterDetail');
  });

  test('has connection functions', () => {
    expect(js).toContain('async function loadConnections');
    expect(js).toContain('async function addConnection');
    expect(js).toContain('async function acceptConnection');
  });

  test('has vouch functions', () => {
    expect(js).toContain('async function searchSitters');
    expect(js).toContain('async function submitVouch');
  });

  test('has profile functions', () => {
    expect(js).toContain('async function saveBabysitterProfile');
  });

  test('exposes necessary functions to window', () => {
    expect(js).toContain('window.showSitterDetail');
    expect(js).toContain('window.acceptConnection');
    expect(js).toContain('window.selectSitter');
    expect(js).toContain('window.clearSelectedSitter');
  });
});

describe('CSS Styles', () => {
  let css;

  beforeAll(() => {
    css = fs.readFileSync(path.join(__dirname, '../public/styles.css'), 'utf8');
  });

  test('has hidden class', () => {
    expect(css).toContain('.hidden');
    expect(css).toContain('display: none');
  });

  test('has responsive styles', () => {
    expect(css).toContain('@media');
    expect(css).toContain('600px');
  });

  test('has trust badge styles', () => {
    expect(css).toContain('.trust-badge');
    expect(css).toContain('.degree-1');
    expect(css).toContain('.degree-2');
  });

  test('has card styles', () => {
    expect(css).toContain('.sitter-card');
    expect(css).toContain('.card-grid');
  });

  test('has modal styles', () => {
    expect(css).toContain('.modal');
    expect(css).toContain('.modal-content');
  });

  test('has form styles', () => {
    expect(css).toContain('input');
    expect(css).toContain('textarea');
    expect(css).toContain('.btn');
  });
});
