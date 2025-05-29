let token = localStorage.getItem('token');
const loginSection = document.getElementById('loginSection');
const dashboard = document.getElementById('dashboard');
const loginError = document.getElementById('loginError');

function showDashboard() {
  loginSection.classList.add('hidden');
  dashboard.classList.remove('hidden');
  loadLocks();
  loadGroups();
}

function showLogin() {
  dashboard.classList.add('hidden');
  loginSection.classList.remove('hidden');
}

if (token) {
  showDashboard();
}

// Login form
const loginForm = document.getElementById('loginForm');
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  const res = await fetch('/user/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  if (res.ok) {
    const data = await res.json();
    token = data.token;
    localStorage.setItem('token', token);
    showDashboard();
  } else {
    loginError.textContent = 'Innlogging feilet';
  }
});

// Load locks
async function loadLocks() {
  const res = await fetch('/lock', {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const list = document.getElementById('lockList');
  list.innerHTML = '';
  if (res.ok) {
    const locks = await res.json();
    for (const lock of locks) {
      const li = document.createElement('li');
      li.textContent = `${lock.id}: ${lock.name} (${lock.status})`;
      list.appendChild(li);
    }
  } else {
    list.textContent = 'Kunne ikke hente låser';
  }
}

document.getElementById('refreshLocks').onclick = loadLocks;

// Create lock
const createLockForm = document.getElementById('createLockForm');
createLockForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = document.getElementById('lockName').value;
  const type = document.getElementById('lockType').value;
  let adapterData;
  try { adapterData = JSON.parse(document.getElementById('adapterData').value); } catch { adapterData = {}; }
  const res = await fetch('/lock', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
    body: JSON.stringify({ name, type, adapter_data: adapterData })
  });
  if (res.ok) {
    alert('Lås opprettet');
    loadLocks();
  } else {
    alert('Feil ved opprettelse av lås');
  }
});

// Load groups
async function loadGroups() {
  const res = await fetch('/accessgroup/list', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
    body: JSON.stringify({ token })
  });
  const list = document.getElementById('groupList');
  list.innerHTML = '';
  if (res.ok) {
    const groups = await res.json();
    for (const g of groups) {
      const li = document.createElement('li');
      li.textContent = `${g.id}: ${g.name} (${g.role})`;
      list.appendChild(li);
    }
  } else {
    list.textContent = 'Kunne ikke hente grupper';
  }
}

document.getElementById('refreshGroups').onclick = loadGroups;

// Create group
const createGroupForm = document.getElementById('createGroupForm');
createGroupForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = document.getElementById('groupName').value;
  const res = await fetch('/accessgroup/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
    body: JSON.stringify({ name })
  });
  if (res.ok) {
    alert('Gruppe opprettet');
    loadGroups();
  } else {
    alert('Feil ved opprettelse av gruppe');
  }
});
