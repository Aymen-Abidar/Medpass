const API = '/api';
const qs = (s, r = document) => r.querySelector(s);
const getToken = () => localStorage.getItem('medpass_token') || '';
const getUser = () => { try { return JSON.parse(localStorage.getItem('medpass_user') || 'null'); } catch { return null; } };
const setSession = (token, user) => { localStorage.setItem('medpass_token', token); localStorage.setItem('medpass_user', JSON.stringify(user)); };
const clearSession = () => { localStorage.removeItem('medpass_token'); localStorage.removeItem('medpass_user'); sessionStorage.removeItem('medpass_doctor_pin'); };
const getDoctorPin = () => sessionStorage.getItem('medpass_doctor_pin') || '';
const setDoctorPin = pin => sessionStorage.setItem('medpass_doctor_pin', pin);
const logout = () => { clearSession(); location.href = '/login.html'; };
const parseList = text => text.split('\n').map(x => x.trim()).filter(Boolean);
const fmtDate = s => s ? new Date(s).toLocaleString() : '—';
const escapeHtml = s => String(s || '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const renderBadges = items => !items || !items.length ? '<span class="muted">Aucune donnée</span>' : items.map(i => `<span class="array-item">${escapeHtml(i)}</span>`).join('');
const jsonHeaders = (extra={}) => {
  const h = {'Content-Type':'application/json', ...extra};
  const t = getToken(); if (t) h.Authorization = `Bearer ${t}`;
  const pin = getDoctorPin(); if (pin) h['X-Doctor-PIN'] = pin;
  return h;
};
async function api(path, opts={}) {
  const res = await fetch(`${API}${path}`, opts);
  const isJson = (res.headers.get('content-type') || '').includes('application/json');
  const data = isJson ? await res.json() : await res.text();
  if (!res.ok) throw new Error(data.detail || data.message || 'Erreur');
  return data;
}
function flash(el, msg, type='info'){ if(el) el.innerHTML = `<div class="message ${type}">${msg}</div>`; }
function protect(role){ const u=getUser(); if(!u||!getToken()){ location.href='/login.html'; return null;} if(role&&u.role!==role){ location.href=u.role==='doctor'?'/doctor.html':'/client.html'; return null;} return u; }
function hardenCredentialForms(root=document){
  root.querySelectorAll('form[data-no-autofill="true"]').forEach(form=>{
    form.setAttribute('autocomplete','off');
    form.setAttribute('data-lpignore','true');
    form.setAttribute('data-1p-ignore','true');
    form.setAttribute('data-bwignore','true');
    form.querySelectorAll('input[type="email"], input[type="password"], input[data-sensitive="true"]').forEach(input=>{
      if(input.type === 'password'){
        input.setAttribute('autocomplete', 'new-password');
      } else {
        input.setAttribute('autocomplete', 'off');
        input.setAttribute('autocapitalize', 'off');
        input.setAttribute('spellcheck', 'false');
      }
      input.setAttribute('data-lpignore','true');
      input.setAttribute('data-1p-ignore','true');
      input.setAttribute('data-bwignore','true');
      input.setAttribute('readonly','readonly');
      const unlock = () => input.removeAttribute('readonly');
      input.addEventListener('focus', unlock, {once:true});
      input.addEventListener('pointerdown', unlock, {once:true});
      input.addEventListener('keydown', unlock, {once:true});
    });
  });
}

async function initLogin(){
  const lf = qs('#login-form'), rf = qs('#register-form'), role = qs('#register-role'), wrap = qs('#doctor-pin-wrap'), box = qs('#auth-result');
  hardenCredentialForms(document);
  if(role) role.addEventListener('change', ()=>wrap.classList.toggle('hidden', role.value !== 'doctor'));
  if(lf) lf.addEventListener('submit', async e=>{ e.preventDefault(); try{ const payload={ email: lf.elements['login_email'].value.trim(), password: lf.elements['login_password'].value }; const data=await api('/auth/login',{method:'POST',headers:jsonHeaders(),body:JSON.stringify(payload)}); setSession(data.token,data.user); location.href=data.user.role==='doctor'?'/doctor.html':'/client.html'; }catch(err){flash(box,err.message,'error');}});
  if(rf) rf.addEventListener('submit', async e=>{ e.preventDefault(); try{ const payload={ first_name: rf.elements['first_name'].value.trim(), last_name: rf.elements['last_name'].value.trim(), email: rf.elements['register_email'].value.trim(), birth_date: rf.elements['birth_date'].value, password: rf.elements['register_password'].value, role: rf.elements['role'].value, doctor_pin: rf.elements['doctor_pin'].value.trim() }; const data=await api('/auth/register',{method:'POST',headers:jsonHeaders(),body:JSON.stringify(payload)}); setSession(data.token,data.user); if(payload.role==='doctor'&&payload.doctor_pin) setDoctorPin(payload.doctor_pin); location.href=data.user.role==='doctor'?'/doctor.html':'/client.html'; }catch(err){flash(box,err.message,'error');}});
}

async function initClient(){
  const user = protect('patient'); if(!user) return; qs('#logout-btn')?.addEventListener('click',logout); qs('#patient-name').textContent=`${user.first_name} ${user.last_name}`;
  try{ const dossier=await api('/dossier/mon-dossier',{headers:jsonHeaders()}); qs('#blood-type').textContent=dossier.blood_type||'—'; qs('#allergies-list').innerHTML=renderBadges(dossier.public_allergies); qs('#conditions-list').innerHTML=renderBadges(dossier.public_conditions); qs('#emergency-contact').textContent=dossier.emergency_contact_name?`${dossier.emergency_contact_name} — ${dossier.emergency_contact_phone}`:'Non renseigné'; qs('#patient-updated').textContent=fmtDate(dossier.updated_at); qs('#patient-summary').textContent=dossier.private_data?.notes||'Aucune note privée enregistrée.'; const logs=await api('/dossier/logs',{headers:jsonHeaders()}); const c=qs('#access-logs'); c.innerHTML=logs.items.length?logs.items.map(log=>`<div class="log-card"><strong>${log.access_role==='doctor'?'Médecin':'Secours'}</strong><p class="muted">${log.first_name?`${log.first_name} ${log.last_name}`:'Accès public'} • ${log.access_level}</p><p>${fmtDate(log.created_at)} • IP ${log.ip_address||'n/a'}</p></div>`).join(''):'<div class="log-card"><p class="muted">Aucun accès enregistré.</p></div>'; }catch(err){ flash(qs('#client-message'),err.message,'error'); }
}

async function initPatientProfile(){
  const user=protect('patient'); if(!user) return; qs('#logout-btn')?.addEventListener('click',logout); const f=qs('#patient-profile-form'), box=qs('#profile-message');
  try{ const d=await api('/dossier/mon-dossier',{headers:jsonHeaders()}); qs('#pp-name').textContent=`${user.first_name} ${user.last_name}`; f.elements['blood_type'].value=d.blood_type||''; f.elements['public_allergies'].value=(d.public_allergies||[]).join('\n'); f.elements['public_conditions'].value=(d.public_conditions||[]).join('\n'); f.elements['emergency_contact_name'].value=d.emergency_contact_name||''; f.elements['emergency_contact_phone'].value=d.emergency_contact_phone||''; f.elements['emergency_instructions'].value=d.emergency_instructions||''; f.elements['doctor_name'].value=d.private_data?.doctor_name||''; f.elements['doctor_rpps'].value=d.private_data?.doctor_rpps||''; f.elements['treatments'].value=(d.private_data?.treatments||[]).map(x=>x.name||'').join('\n'); f.elements['antecedents'].value=(d.private_data?.antecedents||[]).join('\n'); f.elements['vaccinations'].value=(d.private_data?.vaccinations||[]).map(x=>x.name||'').join('\n'); f.elements['ordonnances'].value=(d.private_data?.ordonnances||[]).map(x=>x.title||'').join('\n'); f.elements['imc'].value=d.private_data?.imc||''; f.elements['blood_pressure'].value=d.private_data?.blood_pressure||''; f.elements['notes'].value=d.private_data?.notes||''; }catch(err){ flash(box,err.message,'error'); }
  f?.addEventListener('submit', async e=>{ e.preventDefault(); const p={ blood_type:f.elements['blood_type'].value.trim(), public_allergies:parseList(f.elements['public_allergies'].value), public_conditions:parseList(f.elements['public_conditions'].value), emergency_contact_name:f.elements['emergency_contact_name'].value.trim(), emergency_contact_phone:f.elements['emergency_contact_phone'].value.trim(), emergency_instructions:f.elements['emergency_instructions'].value.trim(), private_data:{ doctor_name:f.elements['doctor_name'].value.trim(), doctor_rpps:f.elements['doctor_rpps'].value.trim(), treatments:parseList(f.elements['treatments'].value).map(v=>({name:v})), antecedents:parseList(f.elements['antecedents'].value), vaccinations:parseList(f.elements['vaccinations'].value).map(v=>({name:v})), ordonnances:parseList(f.elements['ordonnances'].value).map(v=>({title:v})), imc:f.elements['imc'].value.trim(), blood_pressure:f.elements['blood_pressure'].value.trim(), notes:f.elements['notes'].value.trim() } }; try{ await api('/dossier/mon-dossier',{method:'PUT',headers:jsonHeaders(),body:JSON.stringify(p)}); flash(box,'Profil médical enregistré avec succès.','success'); }catch(err){ flash(box,err.message,'error'); } });
}

async function initPatientQr(){
  const user=protect('patient'); if(!user) return; qs('#logout-btn')?.addEventListener('click',logout); const box=qs('#qr-message');
  async function load(){ try{ const d=await api('/qrcode/generate',{headers:jsonHeaders()}); qs('#qr-image').src=d.image; qs('#qr-token').textContent=d.token; qs('#qr-url').textContent=d.public_url; qs('#open-emergency').href=d.public_url; }catch(err){ flash(box,err.message,'error'); } }
  qs('#regen-qr')?.addEventListener('click', async()=>{ try{ await api('/qrcode/regenerate',{method:'POST',headers:jsonHeaders()}); flash(box,'Nouveau QR généré.','success'); load(); }catch(err){ flash(box,err.message,'error'); } });
  qs('#copy-url')?.addEventListener('click', async()=>{ const text=qs('#qr-url').textContent.trim(); if(text){ await navigator.clipboard.writeText(text); flash(box,'Lien copié.','success'); } });
  load();
}

async function initDoctorPin(){ const user=protect('doctor'); if(!user) return; qs('#logout-btn')?.addEventListener('click',logout); const f=qs('#doctor-pin-form'), box=qs('#pin-message'); if(getDoctorPin()) flash(box,'PIN déjà mémorisé dans cette session.','success'); f?.addEventListener('submit', async e=>{ e.preventDefault(); const pin=f.elements['pin'].value.trim(); try{ await api('/doctor/verify-pin',{method:'POST',headers:jsonHeaders(),body:JSON.stringify({pin})}); setDoctorPin(pin); flash(box,'PIN validé.','success'); }catch(err){ flash(box,err.message,'error'); } }); }

async function initDoctor(){ const user=protect('doctor'); if(!user) return; qs('#logout-btn')?.addEventListener('click',logout); qs('#doctor-name').textContent=`${user.first_name} ${user.last_name}`; const box=qs('#doctor-message'); try{ const d=await api('/patients',{headers:jsonHeaders()}); qs('#doctor-count').textContent=d.items.length; qs('#critical-count').textContent=d.items.filter(x=>(x.public_allergies||[]).length).length; qs('#archived-count').textContent=d.items.filter(x=>x.is_archived).length; qs('#doctor-patient-list').innerHTML=d.items.length?d.items.map(p=>`<div class="patient-card"><div class="split"><div><h4>${escapeHtml(p.first_name)} ${escapeHtml(p.last_name)}</h4><p class="muted">${escapeHtml(p.email)} • Groupe ${escapeHtml(p.blood_type||'—')}</p></div><span class="status-pill ${p.is_archived?'danger':'success'}">${p.is_archived?'Archivé':'Actif'}</span></div><div class="array-list" style="margin:10px 0 12px;">${renderBadges(p.public_conditions||[])}</div><div class="split"><span class="muted">Allergies: ${(p.public_allergies||[]).length}</span><a class="btn btn-secondary" href="/doctor-patient.html?id=${p.id}">Ouvrir le dossier</a></div></div>`).join(''):'<div class="patient-card"><p class="muted">Aucun patient.</p></div>'; }catch(err){ flash(box,err.message+' — ouvre la page PIN si besoin.','error'); } }

async function initDoctorForm(){ const user=protect('doctor'); if(!user) return; qs('#logout-btn')?.addEventListener('click',logout); const f=qs('#doctor-create-patient-form'), box=qs('#doctor-form-message'); hardenCredentialForms(f.closest('body') || document); f?.addEventListener('submit', async e=>{ e.preventDefault(); const p={ email:f.elements['patient_email'].value.trim(), password:f.elements['patient_password'].value.trim(), first_name:f.elements['first_name'].value.trim(), last_name:f.elements['last_name'].value.trim(), birth_date:f.elements['birth_date'].value.trim(), blood_type:f.elements['blood_type'].value.trim(), public_allergies:parseList(f.elements['public_allergies'].value), public_conditions:parseList(f.elements['public_conditions'].value), emergency_contact_name:f.elements['emergency_contact_name'].value.trim(), emergency_contact_phone:f.elements['emergency_contact_phone'].value.trim(), emergency_instructions:f.elements['emergency_instructions'].value.trim(), private_data:{ doctor_name:f.elements['doctor_name'].value.trim(), doctor_rpps:f.elements['doctor_rpps'].value.trim(), treatments:parseList(f.elements['treatments'].value).map(v=>({name:v})), antecedents:parseList(f.elements['antecedents'].value), vaccinations:parseList(f.elements['vaccinations'].value).map(v=>({name:v})), ordonnances:parseList(f.elements['ordonnances'].value).map(v=>({title:v})), imc:f.elements['imc'].value.trim(), blood_pressure:f.elements['blood_pressure'].value.trim(), notes:f.elements['notes'].value.trim() } }; try{ const d=await api('/patients',{method:'POST',headers:jsonHeaders(),body:JSON.stringify(p)}); flash(box,`Patient créé: ${d.first_name} ${d.last_name}.`,'success'); f.reset(); }catch(err){ flash(box,err.message+' — vérifie ton PIN.','error'); } }); }

async function initDoctorPatient(){ const user=protect('doctor'); if(!user) return; qs('#logout-btn')?.addEventListener('click',logout); const box=qs('#doctor-patient-message'); const id=new URLSearchParams(location.search).get('id'); if(!id){ flash(box,'ID patient manquant.','error'); return; } const f=qs('#doctor-patient-update-form'); async function load(){ try{ const d=await api(`/patients/${id}`,{headers:jsonHeaders()}); qs('#patient-title').textContent=`${d.first_name} ${d.last_name}`; qs('#patient-subtitle').textContent=`${d.email} • ${d.birth_date||'Date inconnue'}`; qs('#dp-blood').textContent=d.blood_type||'—'; qs('#dp-contact').textContent=d.emergency_contact_name?`${d.emergency_contact_name} — ${d.emergency_contact_phone}`:'Non renseigné'; qs('#dp-allergies').innerHTML=renderBadges(d.public_allergies); qs('#dp-conditions').innerHTML=renderBadges(d.public_conditions); qs('#dp-notes').textContent=d.private_data?.notes||'Aucune note.'; f.elements['blood_type'].value=d.blood_type||''; f.elements['public_allergies'].value=(d.public_allergies||[]).join('\n'); f.elements['public_conditions'].value=(d.public_conditions||[]).join('\n'); f.elements['emergency_contact_name'].value=d.emergency_contact_name||''; f.elements['emergency_contact_phone'].value=d.emergency_contact_phone||''; f.elements['emergency_instructions'].value=d.emergency_instructions||''; f.elements['doctor_name'].value=d.private_data?.doctor_name||''; f.elements['doctor_rpps'].value=d.private_data?.doctor_rpps||''; f.elements['treatments'].value=(d.private_data?.treatments||[]).map(x=>x.name||'').join('\n'); f.elements['antecedents'].value=(d.private_data?.antecedents||[]).join('\n'); f.elements['vaccinations'].value=(d.private_data?.vaccinations||[]).map(x=>x.name||'').join('\n'); f.elements['ordonnances'].value=(d.private_data?.ordonnances||[]).map(x=>x.title||'').join('\n'); f.elements['imc'].value=d.private_data?.imc||''; f.elements['blood_pressure'].value=d.private_data?.blood_pressure||''; f.elements['notes'].value=d.private_data?.notes||''; }catch(err){ flash(box,err.message+' — ouvre /doctor-pin.html pour valider ton PIN.','error'); } }
  f?.addEventListener('submit', async e=>{ e.preventDefault(); const p={ blood_type:f.elements['blood_type'].value.trim(), public_allergies:parseList(f.elements['public_allergies'].value), public_conditions:parseList(f.elements['public_conditions'].value), emergency_contact_name:f.elements['emergency_contact_name'].value.trim(), emergency_contact_phone:f.elements['emergency_contact_phone'].value.trim(), emergency_instructions:f.elements['emergency_instructions'].value.trim(), private_data:{ doctor_name:f.elements['doctor_name'].value.trim(), doctor_rpps:f.elements['doctor_rpps'].value.trim(), treatments:parseList(f.elements['treatments'].value).map(v=>({name:v})), antecedents:parseList(f.elements['antecedents'].value), vaccinations:parseList(f.elements['vaccinations'].value).map(v=>({name:v})), ordonnances:parseList(f.elements['ordonnances'].value).map(v=>({title:v})), imc:f.elements['imc'].value.trim(), blood_pressure:f.elements['blood_pressure'].value.trim(), notes:f.elements['notes'].value.trim() } }; try{ await api(`/patients/${id}`,{method:'PUT',headers:jsonHeaders(),body:JSON.stringify(p)}); flash(box,'Dossier patient mis à jour.','success'); load(); }catch(err){ flash(box,err.message,'error'); } });
  qs('#archive-patient')?.addEventListener('click', async()=>{ if(!confirm('Archiver ce patient ?')) return; try{ await api(`/patients/${id}`,{method:'DELETE',headers:jsonHeaders()}); flash(box,'Patient archivé.','success'); load(); }catch(err){ flash(box,err.message,'error'); } });
  load(); }

async function initScanner(){ const f=qs('#scanner-form'), box=qs('#scanner-message'); f?.addEventListener('submit', async e=>{ e.preventDefault(); const token=f.elements['token'].value.trim(); try{ const c=await api(`/qrcode/verify/${encodeURIComponent(token)}`); if(!c.valid) throw new Error('Token invalide.'); location.href=`/emergency.html?token=${encodeURIComponent(token)}`; }catch(err){ flash(box,err.message,'error'); } }); }

async function initEmergency(){ const params=new URLSearchParams(location.search); const token=params.get('token'); const f=qs('#emergency-search-form'), box=qs('#emergency-message'); f?.addEventListener('submit', e=>{ e.preventDefault(); const t=f.elements['token'].value.trim(); location.href=`/emergency.html?token=${encodeURIComponent(t)}`; }); if(!token) return; try{ const d=await api(`/dossier/public/${encodeURIComponent(token)}`); qs('#emergency-name').textContent=`${d.first_name} ${d.last_name}`; qs('#emergency-blood').textContent=d.blood_type||'—'; qs('#emergency-id').textContent=d.medpass_id||'—'; qs('#emergency-contact').textContent=d.emergency_contact_name?`${d.emergency_contact_name} — ${d.emergency_contact_phone}`:'Non renseigné'; qs('#emergency-allergies').innerHTML=renderBadges(d.public_allergies); qs('#emergency-conditions').innerHTML=renderBadges(d.public_conditions); qs('#emergency-instructions').textContent=d.emergency_instructions||'Aucune consigne spécifique.'; }catch(err){ flash(box,err.message,'error'); } }

document.addEventListener('DOMContentLoaded', ()=>{ hardenCredentialForms(document); const page=document.body.dataset.page; ({login:initLogin,client:initClient,patientProfile:initPatientProfile,patientQr:initPatientQr,doctor:initDoctor,doctorForm:initDoctorForm,doctorPin:initDoctorPin,doctorPatient:initDoctorPatient,scanner:initScanner,emergency:initEmergency}[page]||(()=>{}))(); });
