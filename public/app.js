const API_BASE = '/api';
const TOKEN_KEY = 'medpass_token';
const USER_KEY = 'medpass_user';
const DOCTOR_PIN_KEY = 'medpass_doctor_pin_meta';
const DOCTOR_PIN_TTL_MS = 60 * 60 * 1000;

const qs = (sel, root = document) => root.querySelector(sel);
const qsa = (sel, root = document) => [...root.querySelectorAll(sel)];
const getToken = () => localStorage.getItem(TOKEN_KEY) || '';
const setToken = (token) => localStorage.setItem(TOKEN_KEY, token);
const clearToken = () => localStorage.removeItem(TOKEN_KEY);
const getUser = () => { try { return JSON.parse(localStorage.getItem(USER_KEY) || 'null'); } catch { return null; } };
const setUser = (user) => localStorage.setItem(USER_KEY, JSON.stringify(user));
const clearUser = () => localStorage.removeItem(USER_KEY);

function getDoctorPinMeta(){
  try { return JSON.parse(sessionStorage.getItem(DOCTOR_PIN_KEY) || 'null'); } catch { return null; }
}
function getDoctorPin(){
  const meta = getDoctorPinMeta();
  if(!meta || !meta.pin || !meta.at) return '';
  if(Date.now() - meta.at > DOCTOR_PIN_TTL_MS){ clearDoctorPin(); return ''; }
  return meta.pin;
}
function setDoctorPin(pin){ sessionStorage.setItem(DOCTOR_PIN_KEY, JSON.stringify({ pin, at: Date.now() })); }
function clearDoctorPin(){ sessionStorage.removeItem(DOCTOR_PIN_KEY); }

function escapeHtml(value){
  return String(value ?? '').replace(/[&<>"']/g, s => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[s]));
}
function parseList(text){ return String(text || '').split(/\n|,/).map(x => x.trim()).filter(Boolean); }
function renderBadges(items){
  const arr = items || [];
  if(!arr.length) return '<span class="array-item">Aucune</span>';
  return arr.map(item => `<span class="array-item">${escapeHtml(item.title || item)}</span>`).join('');
}

async function api(path, options = {}){
  const headers = new Headers(options.headers || {});
  if(getToken()) headers.set('Authorization', `Bearer ${getToken()}`);
  const pin = getDoctorPin();
  if(pin) headers.set('X-Doctor-Pin', pin);
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  const contentType = res.headers.get('content-type') || '';
  const data = contentType.includes('application/json') ? await res.json() : await res.text();
  if(!res.ok){ throw new Error((data && data.detail) || 'Une erreur est survenue.'); }
  return data;
}

function showInlineMessage(el, message, type='info'){
  if(!el) return;
  el.className = `message ${type}`;
  el.textContent = message;
}
function ensureActionModal(){
  if(qs('#action-modal')) return;
  document.body.insertAdjacentHTML('beforeend', `
    <div id="action-modal" class="action-modal hidden">
      <div class="action-modal-box">
        <div class="action-modal-icon">✓</div>
        <h3 id="action-modal-title">Succès</h3>
        <p id="action-modal-text"></p>
        <button id="action-modal-close" class="btn btn-primary">Fermer</button>
      </div>
    </div>`);
  qs('#action-modal-close')?.addEventListener('click', () => qs('#action-modal')?.classList.add('hidden'));
}
function ensureVerificationModal(){
  if(qs('#verification-modal')) return;
  document.body.insertAdjacentHTML('beforeend', `
    <div id="verification-modal" class="action-modal hidden">
      <div class="action-modal-box verification-modal-box">
        <div class="action-modal-icon info">#</div>
        <h3 id="verification-modal-title">Vérification de l’e-mail</h3>
        <p id="verification-modal-text">Saisissez le code que nous venons d’envoyer à votre adresse e-mail.</p>
        <form id="verification-modal-form" class="stack" style="margin-top:16px;">
          <div class="label-block" style="text-align:left;">
            <label>Code de vérification</label>
            <input id="verification-code-input" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Entrez le code" required />
          </div>
          <div id="verification-modal-message"></div>
          <div class="hero-actions" style="margin-top:6px;">
            <button type="button" id="verification-cancel" class="btn btn-secondary">Annuler</button>
            <button type="submit" id="verification-submit" class="btn btn-primary">Vérifier</button>
          </div>
        </form>
      </div>
    </div>`);
  qs('#verification-cancel')?.addEventListener('click', () => qs('#verification-modal')?.classList.add('hidden'));
}

function openVerificationModal(email){
  ensureVerificationModal();
  qs('#verification-modal-title').textContent = 'Vérification de l’e-mail';
  qs('#verification-modal-text').textContent = `Un code de vérification a été envoyé à ${email}.`;
  const input = qs('#verification-code-input');
  const box = qs('#verification-modal-message');
  if(box) box.innerHTML = '';
  if(input) input.value = '';
  qs('#verification-modal')?.classList.remove('hidden');
  setTimeout(() => input?.focus(), 30);
}

function showActionModal(message, title='Opération réussie'){
  ensureActionModal();
  qs('#action-modal-title').textContent = title;
  qs('#action-modal-text').textContent = message;
  qs('#action-modal')?.classList.remove('hidden');
}
function success(el, message, title='Opération réussie'){
  showInlineMessage(el, message, 'success');
  showActionModal(message, title);
}

function logout(){
  clearToken(); clearUser(); clearDoctorPin();
  location.href = '/login.html';
}

function mountGlobalNav(page, user){
  const nav = qs('#global-nav');
  if(!nav) return;
  let links = [];
  if(user?.role === 'patient'){
    links = [
      ['/client.html', 'Accueil patient', page === 'client'],
      ['/patient-profile.html', 'Mon profil', page === 'patientProfile'],
      ['/patient-qr.html', 'Mon QR', page === 'patientQr'],
      ['/scanner.html', 'Scanner', page === 'scanner'],
    ];
  } else if(user?.role === 'doctor'){
    links = [
      ['/doctor.html', 'Dashboard', page === 'doctor' && !location.search.includes('view=archived')],
      ['/doctor.html?view=archived', 'Archived', location.search.includes('view=archived')],
      ['/doctor-form.html', 'Créer / lier un patient', page === 'doctorForm'],
      ['/doctor-pin.html', 'Valider PIN', page === 'doctorPin'],
      ['/scanner.html', 'Scanner', page === 'scanner'],
    ];
  } else {
    links = [
      ['/', 'Accueil', page === 'landing'],
      ['/login.html', 'Entrer dans l’app', page === 'login'],
      ['/signup.html', 'Créer un compte', page === 'signup'],
      ['/scanner.html', 'Scanner', page === 'scanner'],
    ];
  }
  nav.innerHTML = links.map(([href, label, active]) => `<a class="nav-link ${active ? 'active' : ''}" href="${href}">${label}</a>`).join('');
}

function protect(expectedRole){
  const user = getUser();
  if(!getToken() || !user){ location.href = '/login.html'; return null; }
  if(user.role !== expectedRole){ location.href = user.role === 'doctor' ? '/doctor.html' : '/client.html'; return null; }
  if(user.role === 'patient' && user.must_complete_onboarding && !location.pathname.endsWith('/onboarding.html')){
    location.href = '/onboarding.html'; return null;
  }
  return user;
}

async function refreshUser(){
  try {
    const me = await api('/auth/me');
    const user = { ...getUser(), ...me };
    setUser(user);
    return user;
  } catch {
    return getUser();
  }
}

async function initLogin(){
  mountGlobalNav('login', null);
  const form = qs('#login-form');
  const box = qs('#auth-result');
  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const data = await api('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: form.elements['login_email'].value.trim(),
          password: form.elements['login_password'].value,
        }),
      });
      setToken(data.token);
      setUser(data.user);
      if(data.user.must_complete_onboarding){
        location.href = '/onboarding.html';
        return;
      }
      location.href = data.user.role === 'doctor' ? '/doctor.html' : '/client.html';
    } catch (err) {
      showInlineMessage(box, err.message, 'error');
    }
  });
}

async function initSignup(){
  mountGlobalNav('signup', null);
  ensureVerificationModal();
  const form = qs('#signup-form');
  const roleSelect = qs('#signup-role');
  const pinWrap = qs('#doctor-pin-wrap');
  const box = qs('#signup-result');
  let pendingSignupPayload = null;

  roleSelect?.addEventListener('change', () => pinWrap?.classList.toggle('hidden', roleSelect.value !== 'doctor'));

  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      first_name: form.elements['first_name'].value.trim(),
      last_name: form.elements['last_name'].value.trim(),
      email: form.elements['email'].value.trim(),
      phone_number: form.elements['phone_number'].value.trim(),
      birth_date: form.elements['birth_date'].value,
      role: form.elements['role'].value,
      doctor_pin: form.elements['doctor_pin']?.value.trim(),
      password: form.elements['password'].value,
    };
    if(payload.role === 'doctor' && (!payload.doctor_pin || payload.doctor_pin.length !== 4)){
      showInlineMessage(box, 'Le médecin doit saisir un PIN à 4 chiffres.', 'error');
      return;
    }
    try {
      const data = await api('/auth/send-email-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: payload.email, purpose: 'signup' }),
      });
      pendingSignupPayload = payload;
      let msg = 'Le code de vérification a été envoyé automatiquement à votre e-mail.';
      if(data.dev_code) msg += ` Code local: ${data.dev_code}`;
      showInlineMessage(box, msg, 'success');
      openVerificationModal(payload.email);
    } catch (err) {
      showInlineMessage(box, err.message, 'error');
    }
  });

  qs('#verification-modal-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const modalBox = qs('#verification-modal-message');
    const code = qs('#verification-code-input')?.value.trim();
    if(!pendingSignupPayload){
      showInlineMessage(modalBox, 'Veuillez remplir le formulaire d’inscription avant de vérifier le code.', 'error');
      qs('#verification-modal')?.classList.add('hidden');
      return;
    }
    if(!code){
      showInlineMessage(modalBox, 'Saisissez le code de vérification reçu par e-mail.', 'error');
      return;
    }
    try {
      const data = await api('/auth/register-verified', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...pendingSignupPayload, verification_code: code }),
      });
      setToken(data.token);
      setUser(data.user);
      qs('#verification-modal')?.classList.add('hidden');
      form.reset();
      pinWrap?.classList.add('hidden');
      pendingSignupPayload = null;
      success(box, 'Compte créé avec succès.', 'Compte créé');
      setTimeout(() => {
        location.href = data.user.role === 'doctor' ? '/doctor.html' : '/client.html';
      }, 900);
    } catch (err) {
      showInlineMessage(modalBox, err.message, 'error');
    }
  });
}

async function initOnboarding(){
  const user = protect('patient'); if(!user) return;
  mountGlobalNav('onboarding', user);
  const form = qs('#onboarding-form');
  const box = qs('#onboarding-result');
  qs('#onboarding-email').textContent = user.email;
  qs('#onboarding-email-input').value = user.email;
  qs('#send-onboarding-code')?.addEventListener('click', async () => {
    try {
      const data = await api('/auth/send-email-code', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: user.email, purpose: 'onboarding' }),
      });
      let msg = 'Code de confirmation envoyé.';
      if(data.dev_code) msg += ` Code local: ${data.dev_code}`;
      success(box, msg, 'Code envoyé');
    } catch(err){ showInlineMessage(box, err.message, 'error'); }
  });
  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const data = await api('/auth/complete-onboarding', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: user.email,
          verification_code: form.elements['verification_code'].value.trim(),
          new_password: form.elements['new_password'].value,
          phone_number: form.elements['phone_number'].value.trim(),
        }),
      });
      setToken(data.token); setUser(data.user);
      location.href = '/client.html';
    } catch(err){ showInlineMessage(box, err.message, 'error'); }
  });
}

async function initClient(){
  let user = protect('patient'); if(!user) return;
  user = await refreshUser();
  mountGlobalNav('client', user);
  qs('#logout-btn')?.addEventListener('click', logout);
  const box = qs('#client-message');
  try {
    const dossier = await api('/dossier/mon-dossier');
    qs('#patient-name').textContent = `${user.first_name} ${user.last_name}`;
    qs('#blood-type').textContent = dossier.blood_type || 'À compléter';
    qs('#allergies-list').innerHTML = renderBadges(dossier.public_allergies);
    qs('#conditions-list').innerHTML = renderBadges(dossier.public_conditions);
    qs('#patient-updated').textContent = dossier.updated_at ? new Date(dossier.updated_at).toLocaleDateString('fr-FR') : '—';
    qs('#emergency-contact').textContent = dossier.emergency_contact_name ? `${dossier.emergency_contact_name} — ${dossier.emergency_contact_phone}` : 'À compléter dans le profil';
    qs('#patient-summary').textContent = dossier.linked_to_doctor ? 'Votre dossier médical privé est complété par votre médecin.' : 'Aucun médecin ne vous a encore lié à son espace.';
    renderAppointments(dossier.appointments || []);
  } catch(err){ showInlineMessage(box, err.message, 'error'); }
  qs('#appointment-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    try {
      const data = await api('/patient/appointments', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ date: form.elements['date'].value, time: form.elements['time'].value, title: form.elements['title'].value.trim() }),
      });
      renderAppointments(data.items || []);
      form.reset();
      success(box, 'Rendez-vous ajouté avec succès.');
    } catch(err){ showInlineMessage(box, err.message, 'error'); }
  });
}

function renderAppointments(items){
  const list = qs('#appointments-list');
  if(!list) return;
  if(!items.length){ list.innerHTML = '<div class="patient-card"><p class="muted">Aucun rendez-vous enregistré.</p></div>'; return; }
  list.innerHTML = items.map((item, index) => `
    <div class="patient-card">
      <div class="split"><div><h4>${escapeHtml(item.title)}</h4><p class="muted">${escapeHtml(item.date)} ${item.time ? '• ' + escapeHtml(item.time) : ''}</p></div>
      <button class="btn btn-secondary" data-delete-appointment="${index}">Supprimer</button></div>
    </div>`).join('');
  qsa('[data-delete-appointment]').forEach(btn => btn.addEventListener('click', async () => {
    try {
      const data = await api(`/patient/appointments/${btn.dataset.deleteAppointment}`, { method: 'DELETE' });
      renderAppointments(data.items || []);
      success(qs('#client-message'), 'Rendez-vous supprimé avec succès.');
    } catch(err){ showInlineMessage(qs('#client-message'), err.message, 'error'); }
  }));
}

async function initPatientProfile(){
  let user = protect('patient'); if(!user) return;
  user = await refreshUser();
  mountGlobalNav('patientProfile', user);
  qs('#logout-btn')?.addEventListener('click', logout);
  const form = qs('#patient-profile-form');
  const box = qs('#profile-message');
  try {
    const dossier = await api('/dossier/mon-dossier');
    qs('#pp-name').textContent = 'Mon profil';
    form.elements['blood_type'].value = dossier.blood_type || '';
    form.elements['emergency_contact_name'].value = dossier.emergency_contact_name || '';
    form.elements['emergency_contact_phone'].value = dossier.emergency_contact_phone || '';
    form.elements['public_allergies'].value = (dossier.public_allergies || []).join('\n');
    form.elements['public_conditions'].value = (dossier.public_conditions || []).join('\n');
    form.elements['emergency_instructions'].value = dossier.emergency_instructions || '';
    qs('#doctor-locked-state').textContent = dossier.linked_to_doctor ? 'Le dossier médical privé est géré par votre médecin.' : 'Le médecin complètera le dossier privé après vous avoir lié à son espace.';
  } catch(err){ showInlineMessage(box, err.message, 'error'); }
  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api('/dossier/mon-dossier', {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          blood_type: form.elements['blood_type'].value.trim(),
          emergency_contact_name: form.elements['emergency_contact_name'].value.trim(),
          emergency_contact_phone: form.elements['emergency_contact_phone'].value.trim(),
          public_allergies: parseList(form.elements['public_allergies'].value),
          public_conditions: parseList(form.elements['public_conditions'].value),
          emergency_instructions: form.elements['emergency_instructions'].value.trim(),
        }),
      });
      success(box, 'Profil patient mis à jour avec succès.');
    } catch(err){ showInlineMessage(box, err.message, 'error'); }
  });
}

async function initPatientQr(){
  const user = protect('patient'); if(!user) return;
  mountGlobalNav('patientQr', user);
  qs('#logout-btn')?.addEventListener('click', logout);
  const box = qs('#qr-message');
  let currentQrImage = '';
  let currentPublicUrl = '';
  let currentToken = '';

  async function load(){
    try {
      const d = await api('/qrcode/generate');
      currentQrImage = d.image || '';
      currentPublicUrl = d.public_url || '';
      currentToken = d.token || '';
      qs('#qr-image').src = currentQrImage;
      qs('#qr-token').textContent = currentToken;
      qs('#qr-url').textContent = currentPublicUrl;
      qs('#open-emergency').href = currentPublicUrl;
    } catch(err){ showInlineMessage(box, err.message, 'error'); }
  }

  qs('#regen-qr')?.addEventListener('click', async () => {
    try { await api('/qrcode/regenerate', { method: 'POST' }); await load(); success(box, 'QR régénéré avec succès.'); }
    catch(err){ showInlineMessage(box, err.message, 'error'); }
  });

  qs('#copy-url')?.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(currentPublicUrl || qs('#qr-url').textContent.trim()); success(box, 'Lien copié avec succès.'); }
    catch(err){ showInlineMessage(box, err.message, 'error'); }
  });

  qs('#download-qr')?.addEventListener('click', () => {
    try {
      if(!currentQrImage) throw new Error('QR introuvable.');
      const a = document.createElement('a');
      a.href = currentQrImage;
      a.download = `medpass-qr-${currentToken || 'patient'}.png`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      success(box, 'QR téléchargé avec succès.');
    } catch(err){ showInlineMessage(box, err.message, 'error'); }
  });

  qs('#print-qr')?.addEventListener('click', () => {
    try {
      if(!currentQrImage) throw new Error('QR introuvable.');
      const w = window.open('', '_blank', 'width=600,height=700');
      if(!w) throw new Error('Impossible d’ouvrir la fenêtre d’impression.');
      w.document.write(`<!DOCTYPE html><html><head><title>Impression QR MedPass</title><style>body{font-family:Arial,sans-serif;padding:24px;text-align:center}img{max-width:320px;width:100%}p{word-break:break-all;color:#334}</style></head><body><h2>QR MedPass</h2><img src="${currentQrImage}" alt="QR MedPass" /><p>${currentPublicUrl}</p></body></html>`);
      w.document.close();
      w.focus();
      w.print();
    } catch(err){ showInlineMessage(box, err.message, 'error'); }
  });

  qs('#share-qr')?.addEventListener('click', async () => {
    try {
      if(!currentPublicUrl) throw new Error('Lien du QR introuvable.');
      if(navigator.share){
        await navigator.share({ title: 'QR MedPass', text: 'Accès secours du patient', url: currentPublicUrl });
        success(box, 'QR partagé avec succès.');
      } else {
        await navigator.clipboard.writeText(currentPublicUrl);
        success(box, 'Le partage n’est pas disponible ici. Le lien a été copié.');
      }
    } catch(err){ if(err?.name !== 'AbortError') showInlineMessage(box, err.message, 'error'); }
  });

  load();
}

async function initDoctorPin(){
  const user = protect('doctor'); if(!user) return;
  mountGlobalNav('doctorPin', user);
  qs('#logout-btn')?.addEventListener('click', logout);
  const form = qs('#doctor-pin-form');
  const box = qs('#pin-message');
  const meta = getDoctorPinMeta();
  if(meta && getDoctorPin()) showInlineMessage(box, 'PIN validé pour cette session pendant 1 heure.', 'success');
  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const data = await api('/doctor/verify-pin', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin: form.elements['pin'].value.trim() }),
      });
      setDoctorPin(form.elements['pin'].value.trim());
      success(box, `PIN validé pour ${data.valid_for_minutes} minutes.`);
    } catch(err){ showInlineMessage(box, err.message, 'error'); }
  });
}

async function initDoctor(){
  const user = protect('doctor'); if(!user) return;
  mountGlobalNav('doctor', user);
  qs('#logout-btn')?.addEventListener('click', logout);
  qs('#doctor-name').textContent = `${user.first_name} ${user.last_name}`;
  const box = qs('#doctor-message');
  const isArchivedView = new URLSearchParams(location.search).get('view') === 'archived';
  try {
    const data = await api(`/patients${isArchivedView ? '?include_archived=true' : ''}`);
    const items = (data.items || []).filter(item => isArchivedView ? item.is_archived : !item.is_archived);
    qs('#doctor-count').textContent = (data.items || []).filter(x => !x.is_archived).length;
    qs('#critical-count').textContent = (data.items || []).filter(x => (x.public_allergies || []).length).length;
    qs('#archived-count').textContent = (data.items || []).filter(x => x.is_archived).length;
    qs('#doctor-section-title').textContent = isArchivedView ? 'Patients archivés' : 'Patients actifs';
    qs('#doctor-patient-list').innerHTML = items.length ? items.map(p => `
      <div class="patient-card">
        <div class="split"><div><h4>${escapeHtml(p.first_name)} ${escapeHtml(p.last_name)}</h4><p class="muted">${escapeHtml(p.email)}${p.phone_number ? ' • ' + escapeHtml(p.phone_number) : ''}</p></div>
        <span class="status-pill ${p.is_archived ? 'danger' : 'success'}">${p.is_archived ? 'Archivé' : 'Actif'}</span></div>
        <div class="array-list" style="margin:10px 0 12px;">${renderBadges(p.public_conditions || [])}</div>
        <div class="split">
          <span class="muted">Allergies: ${(p.public_allergies || []).length}</span>
          ${p.is_archived ? `<button class="btn btn-secondary" data-restore="${p.id}">Désarchiver</button>` : `<a class="btn btn-secondary" href="/doctor-patient.html?id=${p.id}">Ouvrir le dossier</a>`}
        </div>
      </div>`).join('') : '<div class="patient-card"><p class="muted">Aucun patient à afficher.</p></div>';
    qsa('[data-restore]').forEach(btn => btn.addEventListener('click', async () => {
      try { await api(`/patients/${btn.dataset.restore}/restore`, { method: 'POST' }); success(box, 'Patient désarchivé avec succès.'); initDoctor(); }
      catch(err){ showInlineMessage(box, err.message, 'error'); }
    }));
  } catch(err){ showInlineMessage(box, `${err.message} — validez le PIN si nécessaire.`, 'error'); }
}

async function initDoctorForm(){
  const user = protect('doctor'); if(!user) return;
  mountGlobalNav('doctorForm', user);
  qs('#logout-btn')?.addEventListener('click', logout);
  const form = qs('#doctor-create-patient-form');
  const box = qs('#doctor-form-message');
  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const payload = {
        email: form.elements['patient_email'].value.trim(),
        password: form.elements['patient_password'].value,
        first_name: form.elements['first_name'].value.trim(),
        last_name: form.elements['last_name'].value.trim(),
        birth_date: form.elements['birth_date'].value,
        phone_number: form.elements['phone_number'].value.trim(),
        blood_type: form.elements['blood_type'].value.trim(),
        emergency_contact_name: form.elements['emergency_contact_name'].value.trim(),
        emergency_contact_phone: form.elements['emergency_contact_phone'].value.trim(),
        emergency_instructions: form.elements['emergency_instructions'].value.trim(),
        public_allergies: parseList(form.elements['public_allergies'].value),
        public_conditions: parseList(form.elements['public_conditions'].value),
        private_data: {
          doctor_name: form.elements['doctor_name'].value.trim(),
          doctor_rpps: form.elements['doctor_rpps'].value.trim(),
          notes: form.elements['notes'].value.trim(),
          cases: []
        }
      };
      const data = await api('/patients', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      form.reset();
      success(box, `Patient créé ou lié avec succès : ${data.first_name} ${data.last_name}.`, 'Patient enregistré');
    } catch(err){ showInlineMessage(box, `${err.message} — validez votre PIN si nécessaire.`, 'error'); }
  });
}

async function initDoctorPatient(){
  const user = protect('doctor'); if(!user) return;
  mountGlobalNav('doctorPatient', user);
  qs('#logout-btn')?.addEventListener('click', logout);
  const box = qs('#doctor-patient-message');
  const form = qs('#doctor-patient-update-form');
  const id = new URLSearchParams(location.search).get('id');
  if(!id){ showInlineMessage(box, 'Patient introuvable.', 'error'); return; }
  let currentCases = [];
  async function load(){
    try {
      const d = await api(`/patients/${id}`);
      qs('#patient-title').textContent = `${d.first_name} ${d.last_name}`;
      qs('#patient-subtitle').textContent = `${d.email}${d.phone_number ? ' • ' + d.phone_number : ''}`;
      qs('#dp-blood').textContent = d.blood_type || '—';
      qs('#dp-contact').textContent = d.emergency_contact_name ? `${d.emergency_contact_name} — ${d.emergency_contact_phone}` : 'Non renseigné';
      qs('#dp-allergies').innerHTML = renderBadges(d.public_allergies);
      qs('#dp-conditions').innerHTML = renderBadges(d.public_conditions);
      qs('#dp-notes').textContent = d.private_data?.notes || 'Aucune note.';
      currentCases = d.private_data?.cases || [];
      renderCases(currentCases);
      form.elements['blood_type'].value = d.blood_type || '';
      form.elements['emergency_contact_name'].value = d.emergency_contact_name || '';
      form.elements['emergency_contact_phone'].value = d.emergency_contact_phone || '';
      form.elements['public_allergies'].value = (d.public_allergies || []).join('\n');
      form.elements['public_conditions'].value = (d.public_conditions || []).join('\n');
      form.elements['emergency_instructions'].value = d.emergency_instructions || '';
      form.elements['doctor_name'].value = d.private_data?.doctor_name || '';
      form.elements['doctor_rpps'].value = d.private_data?.doctor_rpps || '';
      form.elements['notes'].value = d.private_data?.notes || '';
    } catch(err){ showInlineMessage(box, `${err.message} — validez votre PIN.`, 'error'); }
  }
  function renderCases(items){
    const el = qs('#doctor-cases-list');
    if(!el) return;
    el.innerHTML = items.length ? items.map((item, idx) => `
      <div class="app-card"><div class="split"><div><h4>${escapeHtml(item.title)}</h4><p class="muted">${escapeHtml(item.content)}</p></div>
      <button class="btn btn-secondary" data-delete-case="${idx}">Supprimer</button></div></div>`).join('') : '<div class="app-card"><p class="muted">Aucun cas ajouté.</p></div>';
    qsa('[data-delete-case]').forEach(btn => btn.addEventListener('click', () => { currentCases.splice(Number(btn.dataset.deleteCase), 1); renderCases(currentCases); }));
  }
  qs('#add-case-btn')?.addEventListener('click', () => {
    const title = qs('#case_title')?.value.trim();
    const content = qs('#case_content')?.value.trim();
    if(!title || !content){ showInlineMessage(box, 'Ajoutez un titre et un contenu pour le cas.', 'error'); return; }
    currentCases.push({ title, content });
    qs('#case_title').value = '';
    qs('#case_content').value = '';
    renderCases(currentCases);
  });
  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api(`/patients/${id}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          blood_type: form.elements['blood_type'].value.trim(),
          emergency_contact_name: form.elements['emergency_contact_name'].value.trim(),
          emergency_contact_phone: form.elements['emergency_contact_phone'].value.trim(),
          public_allergies: parseList(form.elements['public_allergies'].value),
          public_conditions: parseList(form.elements['public_conditions'].value),
          emergency_instructions: form.elements['emergency_instructions'].value.trim(),
          private_data: {
            doctor_name: form.elements['doctor_name'].value.trim(),
            doctor_rpps: form.elements['doctor_rpps'].value.trim(),
            notes: form.elements['notes'].value.trim(),
            cases: currentCases,
          }
        })
      });
      success(box, 'Dossier patient mis à jour avec succès.');
      load();
    } catch(err){ showInlineMessage(box, err.message, 'error'); }
  });
  qs('#archive-patient')?.addEventListener('click', async () => {
    if(!confirm('Archiver ce patient ?')) return;
    try { await api(`/patients/${id}`, { method: 'DELETE' }); showActionModal('Patient archivé avec succès.'); location.href = '/doctor.html'; }
    catch(err){ showInlineMessage(box, err.message, 'error'); }
  });
  load();
}

async function initScanner(){
  const user = getUser();
  mountGlobalNav('scanner', user);
  qs('#logout-btn')?.addEventListener('click', logout);
  const form = qs('#scanner-form');
  const box = qs('#scanner-message');
  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const token = form.elements['token'].value.trim();
      const d = await api(`/qrcode/verify/${encodeURIComponent(token)}`);
      if(!d.valid) throw new Error('Token invalide.');
      location.href = `/secours/${encodeURIComponent(token)}`;
    } catch(err){ showInlineMessage(box, err.message, 'error'); }
  });
}

async function initEmergency(){
  const user = getUser();
  mountGlobalNav('emergency', user);
  qs('#logout-btn')?.addEventListener('click', logout);
  const params = new URLSearchParams(location.search);
  const token = params.get('token');
  const box = qs('#emergency-message');
  qs('#emergency-search-form')?.addEventListener('submit', (e) => {
    e.preventDefault();
    const t = e.currentTarget.elements['token'].value.trim();
    location.href = `/secours/${encodeURIComponent(t)}`;
  });
  if(!token) return;
  try {
    const d = await api(`/dossier/public/${encodeURIComponent(token)}`);
    qs('#emergency-name').textContent = `${d.first_name} ${d.last_name}`;
    qs('#emergency-blood').textContent = d.blood_type || '—';
    qs('#emergency-id').textContent = d.medpass_id || '—';
    qs('#emergency-contact').textContent = d.emergency_contact_name ? `${d.emergency_contact_name} — ${d.emergency_contact_phone}` : 'Non renseigné';
    qs('#emergency-allergies').innerHTML = renderBadges(d.public_allergies);
    qs('#emergency-conditions').innerHTML = renderBadges(d.public_conditions);
    qs('#emergency-instructions').textContent = d.emergency_instructions || 'Aucune consigne spécifique.';
  } catch(err){ showInlineMessage(box, err.message, 'error'); }
}

document.addEventListener('DOMContentLoaded', async () => {
  ensureActionModal();
  const page = document.body.dataset.page;
  const initMap = {
    login: initLogin,
    signup: initSignup,
    onboarding: initOnboarding,
    client: initClient,
    patientProfile: initPatientProfile,
    patientQr: initPatientQr,
    doctor: initDoctor,
    doctorForm: initDoctorForm,
    doctorPin: initDoctorPin,
    doctorPatient: initDoctorPatient,
    scanner: initScanner,
    emergency: initEmergency,
  };
  if(initMap[page]) await initMap[page]();
});
