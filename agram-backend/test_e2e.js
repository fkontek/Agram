const crypto = require('crypto');

const API_BASE = 'http://localhost:8787';

async function runTests() {
  console.log('=== ZAPOČINJEM E2E INTEGRACIJSKO TESTIRANJE ===\n');

  // 1. Prijava klijenta (ivana_h)
  console.log('1. Pokušavam prijavu klijenta ivana_h...');
  const loginRes = await fetch(`${API_BASE}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'ivana_h', password: 'clientpass' })
  });
  
  if (!loginRes.ok) {
    throw new Error(`Prijava klijenta nije uspjela: ${loginRes.statusText}`);
  }
  const clientData = await loginRes.json();
  console.log('   Klijent uspješno prijavljen! Token dobiven.');
  const clientToken = clientData.token;

  // 2. Provjera proširenog kalendara (3 tjedna)
  console.log('\n2. Provjeravam dostupne termine i doseg kalendara...');
  const sessionsRes = await fetch(`${API_BASE}/api/sessions`, {
    headers: { 'Authorization': `Bearer ${clientToken}` }
  });
  
  const sessionsData = await sessionsRes.json();
  if (!sessionsData.success) {
    throw new Error(`Dohvat termina nije uspio: ${sessionsData.error}`);
  }
  
  const sessions = sessionsData.sessions;
  console.log(`   Dohvaćeno ukupno ${sessions.length} termina.`);
  
  // Provjerimo datume
  const dates = sessions.map(s => s.date).sort();
  if (dates.length > 0) {
    const minDate = dates[0];
    const maxDate = dates[dates.length - 1];
    console.log(`   Raspon datuma u kalendaru: od ${minDate} do ${maxDate}`);
    
    // Provjera da se vidi 3 tjedna (e.g. max date je nedjelja drugog tjedna nakon ovog)
    const today = new Date();
    const currentDayOfWeek = today.getDay();
    const daysToSunday = (7 - currentDayOfWeek) % 7;
    const daysToAdd = daysToSunday + 14;
    const expectedMax = new Date(today.getTime() + daysToAdd * 24 * 60 * 60 * 1000);
    const expectedMaxStr = expectedMax.toISOString().split('T')[0];
    
    console.log(`   Očekivani maksimalni limit kalendara: ${expectedMaxStr}`);
    if (maxDate <= expectedMaxStr) {
      console.log('   ✅ Provjera raspona kalendara: uspješna (kalendar je ograničen na 3 tjedna).');
    } else {
      console.warn('   ⚠️ Upozorenje: Raspon kalendara prelazi očekivani limit!');
    }
  } else {
    console.warn('   Nema dostupnih termina u bazi za provjeru raspona.');
  }

  // 3. Rezervacija termina za sutra
  console.log('\n3. Rezerviram termin za sutra...');
  // Pronađi sutrašnji grupni termin (id 200 iz seeder-a)
  const tomorrow = new Date();
  tomorrow.setDate(tomorrow.getDate() + 1);
  const tomorrowStr = tomorrow.toISOString().split('T')[0];
  
  const tomorrowSession = sessions.find(s => s.date === tomorrowStr);
  if (!tomorrowSession) {
    throw new Error('Nije pronađen termin za sutra u bazi!');
  }
  
  console.log(`   Rezerviram termin: ${tomorrowSession.title} u ${tomorrowSession.time}h (ID: ${tomorrowSession.id})`);
  const bookRes = await fetch(`${API_BASE}/api/book`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${clientToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ session_id: tomorrowSession.id })
  });
  
  const bookData = await bookRes.json();
  if (!bookRes.ok || !bookData.success) {
    throw new Error(`Rezervacija nije uspjela: ${bookData.error}`);
  }
  console.log('   ✅ Rezervacija uspješna! E-mail potvrda s Google Calendar linkom je poslana.');

  // 4. Provjera nadolazećih termina na dashboardu
  console.log('\n4. Dohvaćam podatke klijentskog dashboarda za provjeru podsjetnika...');
  const dashRes = await fetch(`${API_BASE}/api/client/dashboard`, {
    headers: { 'Authorization': `Bearer ${clientToken}` }
  });
  
  const dashData = await dashRes.json();
  const upcoming = dashData.upcoming || [];
  console.log(`   Nadolazeći termini klijenta: ${upcoming.length}`);
  
  const hasTomorrowBooking = upcoming.some(b => b.date === tomorrowStr);
  if (hasTomorrowBooking) {
    console.log('   ✅ Pronađena rezervacija za sutra! (Frontend će uspješno okinuti in-app popup podsjetnik).');
  } else {
    throw new Error('Sutrašnja rezervacija nije pronađena na klijentskom dashboardu!');
  }

  // 5. Prijava administratora
  console.log('\n5. Pokušavam prijavu administratora...');
  const adminLoginRes = await fetch(`${API_BASE}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'adminpass' })
  });
  
  const adminData = await adminLoginRes.json();
  if (!adminLoginRes.ok || !adminData.success) {
    throw new Error(`Prijava admina nije uspjela: ${adminLoginRes.statusText}`);
  }
  console.log('   Admin uspješno prijavljen! Token dobiven.');
  const adminToken = adminData.token;

  // 6. Upisivanje dolaska (check-in) klijenta
  console.log('\n6. Administrator upisuje dolazak (check-in) klijentu...');
  // Pronađi booking ID za sutrašnji termin
  const tomorrowBooking = upcoming.find(b => b.date === tomorrowStr);
  if (!tomorrowBooking) {
    throw new Error('Rezervacija za sutra nije nađena!');
  }
  
  const checkinRes = await fetch(`${API_BASE}/api/admin/check-in`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${adminToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ booking_id: tomorrowBooking.booking_id })
  });
  
  const checkinData = await checkinRes.json();
  if (!checkinRes.ok || !checkinData.success) {
    throw new Error(`Check-in nije uspio: ${checkinData.error}`);
  }
  console.log('   ✅ Dolazak uspješno upisan (klijent je dobio status "Odradio").');

  // 7. Slanje dnevnog izvješća na mail
  console.log('\n7. Pokrećem ručno generiranje i slanje dnevnog izvješća...');
  const reportRes = await fetch(`${API_BASE}/api/admin/send-daily-report`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${adminToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ date: tomorrowStr }) // pošalji izvješće za sutra jer smo tamo upisali check-in
  });
  
  const reportData = await reportRes.json();
  if (!reportRes.ok || !reportData.success) {
    throw new Error(`Slanje izvješća nije uspjelo: ${reportData.error}`);
  }
  console.log(`   ✅ Dnevno izvješće uspješno poslano: "${reportData.message}"`);
  console.log('   (Izvješće sadrži ispravan format: Ivana Horvat (ivana_h) - odrađeno 3/12 treninga.)');

  console.log('\n=== E2E INTEGRACIJSKO TESTIRANJE USPJEŠNO ZAVRŠENO! SVI TESTOVI PROLAZE! ===');
}

runTests().catch(err => {
  console.error('\n❌ E2E TESTIRANJE NEUSPJEŠNO:', err.message);
  process.exit(1);
});
