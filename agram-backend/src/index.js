/**
 * Cloudflare Worker for Agram Pilates Reformer Studio Backend
 * Handles booking system, user authentication, credits, and admin actions.
 */

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json"
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: corsHeaders
  });
}

// Base64Url encoding/decoding helpers
function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function base64UrlToArrayBuffer(base64url) {
  let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function signHMAC(message, secret) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(message);

  const key = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("HMAC", key, messageData);
  return arrayBufferToBase64Url(signature);
}

async function verifyHMAC(message, signature, secret) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(message);
  const signatureData = base64UrlToArrayBuffer(signature);

  const key = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  return await crypto.subtle.verify("HMAC", key, signatureData, messageData);
}

async function createJWT(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const headerPart = arrayBufferToBase64Url(new TextEncoder().encode(JSON.stringify(header)));
  const payloadPart = arrayBufferToBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const message = `${headerPart}.${payloadPart}`;
  const signaturePart = await signHMAC(message, secret);
  return `${message}.${signaturePart}`;
}

async function verifyJWT(token, secret) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [headerPart, payloadPart, signaturePart] = parts;
  const message = `${headerPart}.${payloadPart}`;

  const isValid = await verifyHMAC(message, signaturePart, secret);
  if (!isValid) return null;

  try {
    const payload = JSON.parse(new TextDecoder().decode(base64UrlToArrayBuffer(payloadPart)));
    if (payload.exp && typeof payload.exp === "number") {
      const now = Math.floor(Date.now() / 1000);
      if (now > payload.exp) {
        return null;
      }
    }
    return payload;
  } catch (e) {
    return null;
  }
}

async function getAuthUser(request, env) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return null;
  }
  const token = authHeader.substring(7);
  const secret = env.JWT_SECRET || "dev-secret-key-change-this-in-prod";
  return await verifyJWT(token, secret);
}

// Hashing utility for SHA-256
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Generate random temporary password
function generateTempPassword() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let password = "Ag-";
  for (let i = 0; i < 6; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return password;
}

// Log activity to database
async function logActivity(env, details) {
  try {
    await env.DB.prepare("INSERT INTO ActivityLogs (details) VALUES (?)").bind(details).run();
  } catch (e) {
    console.error("Greška pri bilježenju aktivnosti:", e);
  }
}

// Get current date and time in Croatia timezone (Europe/Zagreb)
function getCroatiaNow() {
  const d = new Date();
  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone: "Europe/Zagreb",
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false
  });
  const parts = formatter.formatToParts(d);
  const partVal = type => parts.find(p => p.type === type).value;
  return new Date(`${partVal('year')}-${partVal('month')}-${partVal('day')}T${partVal('hour')}:${partVal('minute')}:${partVal('second')}`);
}

// Format Date object to YYYY-MM-DD
function formatDate(dateObj) {
  const year = dateObj.getFullYear();
  const month = String(dateObj.getMonth() + 1).padStart(2, '0');
  const day = String(dateObj.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

// Format Date object to YYYY-MM-DDTHH:MM:SS
function formatLocalDateTimeISO(dateObj) {
  const year = dateObj.getFullYear();
  const month = String(dateObj.getMonth() + 1).padStart(2, '0');
  const day = String(dateObj.getDate()).padStart(2, '0');
  const hours = String(dateObj.getHours()).padStart(2, '0');
  const minutes = String(dateObj.getMinutes()).padStart(2, '0');
  const seconds = String(dateObj.getSeconds()).padStart(2, '0');
  return `${year}-${month}-${day}T${hours}:${minutes}:${seconds}`;
}

// Calculate base Monday for schedule generation
function getGenerationBaseMonday(dateObj) {
  const day = dateObj.getDay(); // 0 = Sun, 1 = Mon, ..., 6 = Sat
  if (day === 0) {
    // If Sunday, the base Monday is tomorrow (add 1 day)
    return new Date(dateObj.getTime() + 1 * 24 * 60 * 60 * 1000);
  } else {
    // If Monday-Saturday, the base Monday is this week's Monday
    const daysToSubtract = day - 1;
    return new Date(dateObj.getTime() - daysToSubtract * 24 * 60 * 60 * 1000);
  }
}

// Automatically generate weekly schedule for 3 weeks starting from baseMonday (idempotent)
async function autoGenerateWeeks(env, baseMonday) {
  try {
    const instructorName = "Adrijana";
    const morningHours = ["07:00", "08:00", "09:00", "10:00"];
    const afternoonHours = ["16:00", "17:00", "18:00", "19:00", "20:00"];
    const allHours = [...morningHours, ...afternoonHours];

    // Generate Week 1 (baseMonday), Week 2 (baseMonday + 7 days), Week 3 (baseMonday + 14 days)
    for (let weekOffset = 0; weekOffset <= 2; weekOffset++) {
      const mondayDate = new Date(baseMonday.getTime() + weekOffset * 7 * 24 * 60 * 60 * 1000);
      const queries = [];

      for (let dayOffset = 0; dayOffset < 5; dayOffset++) {
        const currentDay = new Date(mondayDate.getTime() + dayOffset * 24 * 60 * 60 * 1000);
        const dateStr = formatDate(currentDay);

        allHours.forEach(time => {
          let type = "grupni";
          let capacity = 4;
          let title = "Grupni trening";

          queries.push(
            env.DB.prepare(`
              INSERT INTO Sessions (title, instructor, date, time, capacity, type)
              SELECT ?, ?, ?, ?, ?, ?
              WHERE NOT EXISTS (
                SELECT 1 FROM Sessions WHERE date = ? AND time = ?
              )
            `).bind(title, instructorName, dateStr, time, capacity, type, dateStr, time)
          );
        });
      }

      if (queries.length > 0) {
        await env.DB.batch(queries);
      }
    }
    console.log(`autoGenerateWeeks: Checked and initialized schedule starting from base Monday ${formatDate(baseMonday)}.`);
  } catch (error) {
    console.error("autoGenerateWeeks failed:", error);
  }
}

// Check if Week 3 Monday has sessions, if not, generate schedules
async function checkAndAutoGenerateSchedules(env) {
  try {
    const croatiaNow = getCroatiaNow();
    const baseMonday = getGenerationBaseMonday(croatiaNow);
    
    // Check if the Monday of Week 3 (baseMonday + 14 days) already has sessions
    const targetMonday = new Date(baseMonday.getTime() + 14 * 24 * 60 * 60 * 1000);
    const targetMondayStr = formatDate(targetMonday);
    
    const hasSessions = await env.DB.prepare("SELECT 1 FROM Sessions WHERE date = ? LIMIT 1").bind(targetMondayStr).first();
    if (!hasSessions) {
      console.log(`checkAndAutoGenerateSchedules: Week 3 Monday (${targetMondayStr}) has no sessions. Triggering generation...`);
      await autoGenerateWeeks(env, baseMonday);
    }
  } catch (error) {
    console.error("checkAndAutoGenerateSchedules failed:", error);
  }
}

// Helper to get limit from package name
function getPackageLimit(packageName) {
  if (!packageName || packageName === "Nema paketa" || packageName === "Bez paketa") {
    return 0;
  }
  const match = packageName.match(/\d+/);
  return match ? parseInt(match[0], 10) : 0;
}

// Send email using Resend API
async function sendEmail(env, to, subject, htmlContent) {
  const apiKey = env.RESEND_API_KEY;
  if (!apiKey) {
    console.warn("RESEND_API_KEY is not defined. Skipping email sending.");
    return false;
  }

  let recipient = to;
  let emailSubject = subject;
  
  // Sandbox mode: if EMAIL_SANDBOX_MODE is true or default sender is used, redirect all emails to the specified test address.
  const isSandbox = env.EMAIL_SANDBOX_MODE !== "false" && (env.EMAIL_SANDBOX_MODE === "true" || !env.EMAIL_FROM_ADDRESS);
  const redirectTo = env.EMAIL_REDIRECT_TO || "filip.kontek@gmail.com";
  
  if (isSandbox && redirectTo) {
    recipient = redirectTo;
    emailSubject = `[TEST ZA: ${to}] ${subject}`;
  }

  const fromAddress = env.EMAIL_FROM_ADDRESS || "Agram Pilates <onboarding@resend.dev>";

  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: fromAddress,
        to: [recipient],
        subject: emailSubject,
        html: htmlContent
      })
    });
    return res.ok;
  } catch (e) {
    console.error("Error sending email:", e);
    return false;
  }
}

// Auto-book first eligible waitlisted user when a session spot opens up
async function notifyWaitlist(env, sessionId) {
  try {
    // 1. Get session details
    const session = await env.DB.prepare("SELECT id, title, date, time, capacity FROM Sessions WHERE id = ?").bind(sessionId).first();
    if (!session) return;

    // 2. Check if there is actually a free spot
    const countObj = await env.DB.prepare(
      "SELECT COUNT(*) as count FROM Bookings WHERE session_id = ? AND status >= 0"
    ).bind(sessionId).first();
    const bookedCount = countObj ? countObj.count : 0;
    if (bookedCount >= session.capacity) return; // No free spot

    // 3. Find waitlisted users ordered by FIFO (earliest first)
    const waitlisted = await env.DB.prepare(`
      SELECT w.id as waitlist_id, w.user_id, c.username, c.email, c.remaining_credits, c.package_expires, c.package_name, c.status
      FROM Waitlists w
      JOIN Clients c ON w.user_id = c.id
      WHERE w.session_id = ?
      ORDER BY w.created_at ASC
    `).bind(sessionId).all();

    if (!waitlisted.results || waitlisted.results.length === 0) return;

    const dateStr = session.date.split('-').reverse().join('.') + '.';
    const todayStr = formatDate(getCroatiaNow());

    // 4. Try to auto-book the first eligible user
    let bookedUser = null;
    for (const user of waitlisted.results) {
      // Skip frozen users
      if (user.status === "frozen") continue;
      // Skip users with no credits
      if (user.remaining_credits <= 0) continue;
      // Skip users with expired package
      if (user.package_expires && user.package_expires < todayStr) continue;
      // Skip users who already have a booking on the same day
      const existingBookingToday = await env.DB.prepare(`
        SELECT b.id FROM Bookings b
        JOIN Sessions s ON b.session_id = s.id
        WHERE b.user_id = ? AND s.date = ? AND b.status >= 0
      `).bind(user.user_id, session.date).first();
      if (existingBookingToday) continue;

      // This user is eligible — auto-book them!
      bookedUser = user;
      break;
    }

    if (bookedUser) {
      // Auto-book: create booking, deduct credit, remove from waitlist, notify
      const confirmMsg = `Automatski ste dodani u termin '${session.title}' (${dateStr} u ${session.time}h) s liste čekanja. Kredit je oduzet.`;
      await env.DB.batch([
        env.DB.prepare("INSERT INTO Bookings (session_id, user_id, status) VALUES (?, ?, 0)").bind(sessionId, bookedUser.user_id),
        env.DB.prepare("UPDATE Clients SET remaining_credits = remaining_credits - 1 WHERE id = ?").bind(bookedUser.user_id),
        env.DB.prepare("DELETE FROM Waitlists WHERE id = ?").bind(bookedUser.waitlist_id),
        env.DB.prepare("INSERT INTO ClientNotifications (user_id, message) VALUES (?, ?)").bind(bookedUser.user_id, confirmMsg)
      ]);

      // Send confirmation email
      const emailSubject = `Dodani ste u termin: ${session.title}`;
      const emailHtml = `
        <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5; border: 1px solid #ebdcc5; border-radius: 6px; max-width: 480px; margin: 0 auto;">
          <h2 style="color: #a98e65; margin-top: 0; text-transform: uppercase; font-size: 1.2rem; border-bottom: 1.5px solid #ebdcc5; padding-bottom: 6px;">Dodani ste u termin!</h2>
          <p>Bok <b>${bookedUser.username}</b>,</p>
          <p>Oslobodilo se mjesto i automatski ste dodani u termin s liste čekanja:</p>
          <table style="border-spacing: 10px; margin-bottom: 20px; font-size: 0.9rem;">
            <tr><td><b>Termin:</b></td><td>${session.title}</td></tr>
            <tr><td><b>Datum i vrijeme:</b></td><td>${dateStr} u ${session.time}h</td></tr>
          </table>
          <p>Oduzet Vam je 1 trening iz paketa. Vidimo se!</p>
          <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 30px;">
          <p style="font-size: 11px; color: #7c7267; text-align: center; margin: 0;">Ova poruka je poslana automatski. Molimo ne odgovarajte na nju.</p>
        </div>
      `;
      await sendEmail(env, bookedUser.email, emailSubject, emailHtml);

      await logActivity(env, `Wait lista → booking: ${bookedUser.username} → ${session.title} (${dateStr}, ${session.time}h)`);
    }
    // Note: Other waitlisted users are NOT removed — they stay for future cancellations
  } catch (e) {
    console.error("Greška u notifyWaitlist:", e);
  }
}

// Auto-confirm bookings starting in less than 12 hours as attended (status = 1)
async function autoConfirmBookings(env) {
  try {
    const nowCroatia = getCroatiaNow();
    
    // Select all bookings that are currently in status = 0 (Reserved)
    const activeBookings = await env.DB.prepare(`
      SELECT b.id, s.date, s.time, c.username
      FROM Bookings b
      JOIN Sessions s ON b.session_id = s.id
      JOIN Clients c ON b.user_id = c.id
      WHERE b.status = 0
    `).all();

    if (activeBookings.results && activeBookings.results.length > 0) {
      const updates = [];
      for (const b of activeBookings.results) {
        const sessionTime = new Date(`${b.date}T${b.time}:00`);
        const diffHours = (sessionTime.getTime() - nowCroatia.getTime()) / (1000 * 60 * 60);
        if (diffHours < 12) {
          // Less than 12 hours remaining, auto-confirm as attended (status = 1)
          updates.push(env.DB.prepare("UPDATE Bookings SET status = 1 WHERE id = ?").bind(b.id));
          await logActivity(env, `Auto check-in: ${b.username} (manje od 12h do termina)`);
        }
      }
      if (updates.length > 0) {
        await env.DB.batch(updates);
      }
    }
  } catch (e) {
    console.error("Error in autoConfirmBookings:", e);
  }
}

// Calculate Monday and Friday date of the current week (Croatia time)
function getWeeklyReportDates() {
  const croatiaNow = getCroatiaNow();
  const currentDay = croatiaNow.getDay(); // 0 = Sun, 1 = Mon, ..., 5 = Fri, 6 = Sat
  
  // We want Monday of the current week
  const daysToSubtract = currentDay === 0 ? 6 : (currentDay - 1);
  
  const monday = new Date(croatiaNow.getTime() - daysToSubtract * 24 * 60 * 60 * 1000);
  const friday = new Date(monday.getTime() + 4 * 24 * 60 * 60 * 1000);
  
  return {
    mondayStr: formatDate(monday),
    fridayStr: formatDate(friday),
    mondayFormatted: formatDate(monday).split('-').reverse().join('.') + '.',
    fridayFormatted: formatDate(friday).split('-').reverse().join('.') + '.'
  };
}

// Generate and send weekly check-in report email to admin
async function sendWeeklyReportEmail(env) {
  try {
    const dates = getWeeklyReportDates();
    
    // 1. Get all sessions for the week
    const sessionsRes = await env.DB.prepare(`
      SELECT id, title, date, time, instructor, type 
      FROM Sessions 
      WHERE date >= ? AND date <= ?
      ORDER BY date ASC, time ASC
    `).bind(dates.mondayStr, dates.fridayStr).all();

    const sessions = sessionsRes.results || [];

    if (sessions.length === 0) {
      console.log(`No sessions scheduled between ${dates.mondayStr} and ${dates.fridayStr}. Skipping weekly report.`);
      return true;
    }

    // 2. Get checked-in attendees for the week (status = 1)
    const attendeesRes = await env.DB.prepare(`
      SELECT b.session_id, c.username, c.full_name, c.email
      FROM Bookings b
      JOIN Clients c ON b.user_id = c.id
      JOIN Sessions s ON b.session_id = s.id
      WHERE s.date >= ? AND s.date <= ? AND b.status = 1
    `).bind(dates.mondayStr, dates.fridayStr).all();

    const attendees = attendeesRes.results || [];

    // Group sessions by date
    const grouped = {};
    sessions.forEach(session => {
      if (!grouped[session.date]) {
        grouped[session.date] = [];
      }
      grouped[session.date].push(session);
    });

    const dayNames = {
      1: "Ponedjeljak",
      2: "Utorak",
      3: "Srijeda",
      4: "Četvrtak",
      5: "Petak",
      6: "Subota",
      0: "Nedjelja"
    };

    let reportHtml = "";

    // Sort dates
    const sortedDates = Object.keys(grouped).sort();
    
    sortedDates.forEach(dateStr => {
      const [y, m, d] = dateStr.split('-').map(Number);
      const localDate = new Date(y, m - 1, d);
      const dayName = dayNames[localDate.getDay()] || "Nepoznato";
      const dateFormatted = `${String(d).padStart(2, '0')}.${String(m).padStart(2, '0')}.${y}.`;

      reportHtml += `
        <div style="margin-top: 12px; margin-bottom: 4px; font-weight: bold; color: #a98e65; font-size: 0.95rem; text-transform: uppercase; border-bottom: 1px solid #ebdcc5; padding-bottom: 2px;">
          ${dayName} (${dateFormatted})
        </div>
      `;

      grouped[dateStr].forEach(session => {
        const sessionAttendees = attendees.filter(a => a.session_id === session.id);
        
        let attendeesListHtml = "";
        if (sessionAttendees.length === 0) {
          attendeesListHtml = `<li style="color: #7c7267; font-style: italic; list-style-type: none; margin-left: 0; padding-left: 0;">Nije bilo odrađenih dolazaka.</li>`;
        } else {
          attendeesListHtml = sessionAttendees.map(att => {
            const displayName = att.full_name ? `${att.full_name} (${att.username})` : att.username;
            return `<li style="margin-bottom: 4px;"><b>${displayName}</b></li>`;
          }).join('');
        }

        reportHtml += `
          <div style="background-color: #ffffff; padding: 6px 10px; border-radius: 4px; border: 1px solid rgba(197, 168, 128, 0.15); margin-bottom: 6px; margin-top: 4px;">
            <div style="font-size: 0.85rem; color: #2c251e; margin-bottom: 2px;">
              <span style="font-weight: bold; border-left: 2px solid #c5a880; padding-left: 6px;">${session.time}h — ${session.title}</span>
              <span style="color: #7c7267; font-size: 0.75rem; margin-left: 5px;">(Trener: ${session.instructor})</span>
            </div>
            <ul style="margin: 0; padding-left: 15px; font-size: 0.8rem; color: #2c251e; line-height: 1.2rem;">
              ${attendeesListHtml}
            </ul>
          </div>
        `;
      });
    });

    const adminEmail = env.ADMIN_REPORT_EMAIL || "adrijana.kontek@gmail.com";
    const subject = `Agram Pilates - Tjedno izvješće o dolascima (${dates.mondayFormatted} - ${dates.fridayFormatted})`;
    
    const htmlContent = `
      <div style="font-family: Arial, sans-serif; padding: 15px; color: #2c251e; background-color: #faf8f5; border: 1px solid #ebdcc5; border-radius: 6px; max-width: 480px; margin: 0 auto;">
        <h2 style="color: #a98e65; border-bottom: 1.5px solid #ebdcc5; padding-bottom: 6px; margin-top: 0; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; font-size: 1.1rem;">
          Tjedno izvješće o dolascima
        </h2>
        <p style="font-size: 0.85rem; font-weight: bold; color: #7c7267; margin: 0 0 12px 0;">
          Razdoblje: ${dates.mondayFormatted} do ${dates.fridayFormatted}
        </p>
        
        <div>
          ${reportHtml}
        </div>
        
        <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 20px; margin-bottom: 10px;">
        <p style="font-size: 10px; color: #7c7267; text-align: center; margin: 0;">
          Ova poruka je poslana automatski iz sustava Agram Pilates.
        </p>
      </div>
    `;

    await sendEmail(env, adminEmail, subject, htmlContent);
    console.log(`Weekly report email sent successfully to ${adminEmail}`);
    return true;
  } catch (e) {
    console.error("Error sending weekly report email:", e);
    return false;
  }
}

// Generate and send daily check-in report email to admin
async function sendDailyReportEmail(env, dateStr = null) {
  try {
    const croatiaNow = getCroatiaNow();
    const todayStr = dateStr || formatDate(croatiaNow); // YYYY-MM-DD
    const dateFormatted = todayStr.split('-').reverse().join('.') + '.';

    // 1. Get all sessions for today
    const sessionsRes = await env.DB.prepare(`
      SELECT id, title, time, instructor, type 
      FROM Sessions 
      WHERE date = ? 
      ORDER BY time ASC
    `).bind(todayStr).all();

    const sessions = sessionsRes.results || [];

    // If there are no sessions, we skip sending
    if (sessions.length === 0) {
      console.log(`No sessions scheduled for ${todayStr}. Skipping daily report email.`);
      return true;
    }

    // 2. Get checked-in attendees for all sessions of today (status = 1 means checked-in / attended)
    const attendeesRes = await env.DB.prepare(`
      SELECT b.session_id, c.username, c.full_name, c.email, c.total_credits, c.remaining_credits
      FROM Bookings b
      JOIN Clients c ON b.user_id = c.id
      JOIN Sessions s ON b.session_id = s.id
      WHERE s.date = ? AND b.status = 1
    `).bind(todayStr).all();

    const attendees = attendeesRes.results || [];

    // 3. Build HTML report
    let sessionsHtml = "";
    
    sessions.forEach(session => {
      const sessionAttendees = attendees.filter(a => a.session_id === session.id);
      
      let attendeesListHtml = "";
      if (sessionAttendees.length === 0) {
        attendeesListHtml = `<li style="color: #7c7267; font-style: italic; list-style-type: none; margin-left: 0; padding-left: 0;">Nije bilo odrađenih dolazaka.</li>`;
      } else {
        attendeesListHtml = sessionAttendees.map(att => {
          const displayName = att.full_name ? `${att.full_name} (${att.username})` : att.username;
          const total = att.total_credits || 0;
          const remaining = att.remaining_credits || 0;
          const done = total - remaining;
          return `<li style="margin-bottom: 4px;"><b>${displayName}</b> - odrađeno ${done}/${total} treninga.</li>`;
        }).join('');
      }

      sessionsHtml += `
        <div style="background-color: #ffffff; padding: 6px 10px; border-radius: 4px; border: 1px solid rgba(197, 168, 128, 0.15); margin-bottom: 6px;">
          <div style="font-size: 0.85rem; color: #2c251e; margin-bottom: 2px;">
            <span style="font-weight: bold; border-left: 2px solid #c5a880; padding-left: 6px;">${session.time}h — ${session.title}</span>
            <span style="color: #7c7267; font-size: 0.75rem; margin-left: 5px;">(Trener: ${session.instructor})</span>
          </div>
          <ul style="margin: 0; padding-left: 15px; font-size: 0.8rem; color: #2c251e; line-height: 1.2rem;">
            ${attendeesListHtml}
          </ul>
        </div>
      `;
    });

    const adminEmail = env.ADMIN_REPORT_EMAIL || "adrijana.kontek@gmail.com";
    const subject = `Agram Pilates - Dnevno izvješće o dolascima za ${dateFormatted}`;
    
    const htmlContent = `
      <div style="font-family: Arial, sans-serif; padding: 15px; color: #2c251e; background-color: #faf8f5; border: 1px solid #ebdcc5; border-radius: 6px; max-width: 480px; margin: 0 auto;">
        <h2 style="color: #a98e65; border-bottom: 1.5px solid #ebdcc5; padding-bottom: 6px; margin-top: 0; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; font-size: 1.1rem;">
          Dnevno izvješće o dolascima
        </h2>
        <p style="font-size: 0.85rem; font-weight: bold; color: #7c7267; margin: 0 0 12px 0;">
          Datum: ${dateFormatted}
        </p>
        
        <div>
          ${sessionsHtml}
        </div>
        
        <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 20px; margin-bottom: 10px;">
        <p style="font-size: 10px; color: #7c7267; text-align: center; margin: 0;">
          Ova poruka je poslana automatski iz sustava Agram Pilates.
        </p>
      </div>
    `;

    await sendEmail(env, adminEmail, subject, htmlContent);
    console.log(`Daily report email sent successfully for ${todayStr} to ${adminEmail}`);
    return true;
  } catch (e) {
    console.error("Error sending daily report email:", e);
    return false;
  }
}

// Send 24-hour email reminders to clients for tomorrow's bookings
async function sendBookingReminders(env) {
  try {
    const croatiaNow = getCroatiaNow();
    const tomorrow = new Date(croatiaNow.getTime() + 24 * 60 * 60 * 1000);
    const tomorrowStr = formatDate(tomorrow);
    
    // Find all bookings for tomorrow where status is Reserved (0) and reminder hasn't been sent (0)
    const activeBookings = await env.DB.prepare(`
      SELECT b.id as booking_id, c.username, c.email, s.title, s.time, s.date
      FROM Bookings b
      JOIN Clients c ON b.user_id = c.id
      JOIN Sessions s ON b.session_id = s.id
      WHERE s.date = ? AND b.status = 0 AND b.reminder_sent = 0
    `).bind(tomorrowStr).all();

    const bookings = activeBookings.results || [];
    const updates = [];

    for (const b of bookings) {
      if (b.email) {
        const dateFormatted = b.date.split('-').reverse().join('.') + '.';
        const emailSubject = `Podsjetnik na trening: ${b.title}`;
        const emailHtml = `
          <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5; border: 1px solid #ebdcc5; border-radius: 6px; max-width: 480px; margin: 0 auto;">
            <h2 style="color: #a98e65; margin-top: 0; text-transform: uppercase; font-size: 1.2rem; border-bottom: 1.5px solid #ebdcc5; padding-bottom: 6px;">Podsjetnik na trening</h2>
            <p>Bok <b>${b.username}</b>,</p>
            <p>Podsjećamo te da sutra imaš rezerviran termin:</p>
            <table style="border-spacing: 10px; margin-bottom: 20px; font-size: 0.9rem;">
              <tr><td><b>Termin:</b></td><td>${b.title}</td></tr>
              <tr><td><b>Datum i vrijeme:</b></td><td>Sutra (${dateFormatted}) u ${b.time}h</td></tr>
            </table>
            <p style="margin-top: 20px;">
              Vidimo se!
            </p>
            <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 30px;">
            <p style="font-size: 11px; color: #7c7267; text-align: center; margin: 0;">Ova poruka je poslana automatski. Molimo ne odgovarajte na nju.</p>
          </div>
        `;
        await sendEmail(env, b.email, emailSubject, emailHtml);
      }
      updates.push(env.DB.prepare("UPDATE Bookings SET reminder_sent = 1 WHERE id = ?").bind(b.booking_id));
    }

    if (updates.length > 0) {
      await env.DB.batch(updates);
    }
  } catch (e) {
    console.error("Error sending booking reminders:", e);
  }
}

// Synchronize Instagram Feed
async function syncInstagramFeed(env) {
  try {
    // 1. Get access token from Settings
    const tokenObj = await env.DB.prepare("SELECT value FROM Settings WHERE key = 'instagram_access_token'").first();
    if (!tokenObj || !tokenObj.value) {
      console.warn("Instagram access token not configured in Settings.");
      return false;
    }
    const token = tokenObj.value;

    // 2. Fetch latest media (limit 6) from Instagram Basic Display API
    const res = await fetch(`https://graph.instagram.com/me/media?fields=id,caption,media_type,media_url,permalink,thumbnail_url,timestamp&limit=6&access_token=${token}`);
    if (!res.ok) {
      const errorText = await res.text();
      console.error("Instagram API error fetching media:", errorText);
      return false;
    }
    const data = await res.json();
    if (!data || !data.data || !Array.isArray(data.data)) {
      console.error("Invalid response from Instagram API:", data);
      return false;
    }

    // 3. Store posts in InstagramPosts table
    const statements = [
      env.DB.prepare("DELETE FROM InstagramPosts")
    ];

    for (const post of data.data) {
      statements.push(
        env.DB.prepare(`
          INSERT INTO InstagramPosts (id, caption, media_type, media_url, permalink, thumbnail_url, timestamp)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(
          post.id,
          post.caption || "",
          post.media_type,
          post.media_url,
          post.permalink,
          post.thumbnail_url || null,
          post.timestamp
        )
      );
    }

    await env.DB.batch(statements);

    // 4. Update last sync time
    const croatiaNow = getCroatiaNow();
    const nowStr = croatiaNow.toISOString().replace('T', ' ').substring(0, 19);
    await env.DB.prepare("INSERT OR REPLACE INTO Settings (key, value) VALUES ('instagram_last_synced_at', ?)").bind(nowStr).run();

    // 5. Automatic token refresh (if updated more than 30 days ago)
    const tokenUpdatedObj = await env.DB.prepare("SELECT value FROM Settings WHERE key = 'instagram_token_updated_at'").first();
    const tokenUpdated = tokenUpdatedObj ? new Date(tokenUpdatedObj.value.replace(" ", "T") + "Z") : null;
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    if (!tokenUpdated || tokenUpdated < thirtyDaysAgo) {
      console.log("Refreshing Instagram access token...");
      const refreshRes = await fetch(`https://graph.instagram.com/refresh_access_token?grant_type=ig_refresh_token&access_token=${token}`);
      if (refreshRes.ok) {
        const refreshData = await refreshRes.json();
        if (refreshData && refreshData.access_token) {
          await env.DB.batch([
            env.DB.prepare("INSERT OR REPLACE INTO Settings (key, value) VALUES ('instagram_access_token', ?)").bind(refreshData.access_token),
            env.DB.prepare("INSERT OR REPLACE INTO Settings (key, value) VALUES ('instagram_token_updated_at', ?)").bind(nowStr)
          ]);
          console.log("Instagram access token successfully refreshed.");
        }
      } else {
        console.error("Failed to refresh Instagram access token:", await refreshRes.text());
      }
    }

    return true;
  } catch (e) {
    console.error("Error syncing Instagram feed:", e);
    return false;
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Handle CORS preflight requests
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    try {
      // --- PUBLIC ENDPOINTS ---

      // LOGIN
      if (request.method === "POST" && url.pathname === "/api/login") {
        const { username, password } = await request.json();
        if (!username || !password) {
          return jsonResponse({ success: false, error: "Korisničko ime/e-mail i lozinka su obavezni." }, 400);
        }

        const hashedPassword = await hashPassword(password);
                const user = await env.DB.prepare(
          "SELECT id, username, email, is_admin, must_change_password, package_name, total_credits, remaining_credits, package_expires, status, questionnaire, full_name, first_name, last_name, phone FROM Clients WHERE (username = ? OR email = ?) AND password = ?"
        ).bind(username, username, hashedPassword).first();

        if (!user) {
          return jsonResponse({ success: false, error: "Pogrešno korisničko ime/e-mail ili lozinka." }, 401);
        }

        const token = await createJWT({
          user_id: user.id,
          is_admin: user.is_admin,
          username: user.username,
          exp: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60 // 30 days
        }, env.JWT_SECRET || "dev-secret-key-change-this-in-prod");

        return jsonResponse({ success: true, user, token });
      }

      // CHECK USERNAME AVAILABILITY
      if (request.method === "GET" && url.pathname === "/api/check-username") {
        const username = url.searchParams.get("username");
        if (!username) {
          return jsonResponse({ success: false, error: "Korisničko ime je obavezno." }, 400);
        }
        const existing = await env.DB.prepare("SELECT id FROM Clients WHERE username = ?").bind(username).first();
        return jsonResponse({ success: true, available: !existing });
      }

      // CHECK EMAIL EXISTENCE
      if (request.method === "GET" && url.pathname === "/api/check-email") {
        const email = url.searchParams.get("email");
        if (!email) {
          return jsonResponse({ success: false, error: "E-mail je obavezan." }, 400);
        }
        const existing = await env.DB.prepare("SELECT id, status FROM Clients WHERE email = ?").bind(email).first();
        if (existing) {
          return jsonResponse({ success: true, exists: true, status: existing.status });
        }
        return jsonResponse({ success: true, exists: false });
      }

      // REGISTER (Public registration, status 'pending' awaiting admin approval)
      if (request.method === "POST" && url.pathname === "/api/register") {
        const { first_name, last_name, username, email, phone } = await request.json();
        
        if (!first_name || !last_name || !username || !email || !phone) {
          return jsonResponse({ success: false, error: "Sva polja su obavezna (ime, prezime, korisničko ime, e-mail i kontakt broj)." }, 400);
        }

        // Check if username already exists
        const existingUsername = await env.DB.prepare("SELECT id FROM Clients WHERE username = ?").bind(username).first();
        if (existingUsername) {
          return jsonResponse({ success: false, error: "Korisničko ime je već zauzeto." }, 400);
        }

        // Check if email already exists
        const existingEmail = await env.DB.prepare("SELECT id FROM Clients WHERE email = ?").bind(email).first();
        if (existingEmail) {
          return jsonResponse({ success: false, error: "Korisnik s ovom e-mail adresom već ima račun." }, 400);
        }

        const fullName = `${first_name.trim()} ${last_name.trim()}`;

        // Insert client with 'pending' status, 'PENDING' password, null questionnaire, full_name, first_name, last_name, phone
        await env.DB.prepare(`
          INSERT INTO Clients (username, email, password, is_admin, must_change_password, package_name, total_credits, remaining_credits, package_expires, status, questionnaire, full_name, first_name, last_name, phone)
          VALUES (?, ?, 'PENDING', 0, 1, 'Nema aktivnog paketa', 0, 0, NULL, 'pending', NULL, ?, ?, ?, ?)
        `).bind(username, email, fullName, first_name.trim(), last_name.trim(), phone.trim()).run();

        await logActivity(env, `Nova registracija: ${fullName}`);

        return jsonResponse({
          success: true,
          message: "Zahtjev za registraciju je poslan! Nakon što administrator odobri Vaš profil, dobit ćete e-mail s privremenom lozinkom za prijavu."
        });
      }

      // CHANGE PASSWORD (must change temp password)
      if (request.method === "POST" && url.pathname === "/api/change-password") {
        const { user_id, old_password, new_password } = await request.json();
        if (!user_id || !old_password || !new_password) {
          return jsonResponse({ success: false, error: "Sva polja su obavezna." }, 400);
        }

        const hashedOld = await hashPassword(old_password);
        const user = await env.DB.prepare("SELECT id FROM Clients WHERE id = ? AND password = ?").bind(user_id, hashedOld).first();
        if (!user) {
          return jsonResponse({ success: false, error: "Trenutna lozinka nije ispravna." }, 401);
        }

        const hashedNew = await hashPassword(new_password);
        await env.DB.prepare("UPDATE Clients SET password = ?, must_change_password = 0 WHERE id = ?").bind(hashedNew, user_id).run();

        return jsonResponse({ success: true, message: "Lozinka je uspješno promijenjena!" });
      }

      // FORGOT PASSWORD (reset via email)
      if (request.method === "POST" && url.pathname === "/api/forgot-password") {
        const { email } = await request.json();
        if (!email) {
          return jsonResponse({ success: false, error: "E-mail adresa je obavezna." }, 400);
        }

        const client = await env.DB.prepare(
          "SELECT id, username, email, status FROM Clients WHERE email = ?"
        ).bind(email).first();

        if (!client) {
          return jsonResponse({ success: false, error: "Korisnik s tom e-mail adresom nije pronađen." }, 404);
        }

        if (client.status === "pending") {
          return jsonResponse({ success: false, error: "Vaš profil još nije odobren. Molimo pričekajte odobrenje administratora." }, 403);
        }

        const tempPass = generateTempPassword();
        const hashedTemp = await hashPassword(tempPass);

        await env.DB.prepare(
          "UPDATE Clients SET password = ?, must_change_password = 1 WHERE id = ?"
        ).bind(hashedTemp, client.id).run();

        await logActivity(env, `Reset lozinke: ${client.username}`);

        // Slanje maila s novom privremenom lozinkom
        const emailSubject = "Pilates Reformer Agram - Reset lozinke";
        const emailHtml = `
          <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5;">
            <h2 style="color: #a98e65;">Ponovno postavljanje lozinke</h2>
            <p>Zatražili ste ponovno postavljanje lozinke za Vaš račun u Pilates Reformer studiju Agram. Vaša nova privremena lozinka je:</p>
            <table style="border-spacing: 10px;">
              <tr><td><b>Korisničko ime:</b></td><td>${client.username}</td></tr>
              <tr><td><b>Privremena lozinka:</b></td><td><code style="background-color: #eee; padding: 3px 6px; border-radius: 3px;">${tempPass}</code></td></tr>
            </table>
            <p style="margin-top: 20px;">
              Molimo Vas da se prijavite koristeći ove podatke, a sustav će Vas odmah zatražiti da postavite novu trajnu lozinku.
            </p>
            <p style="margin-top: 30px;">
              <a href="https://pilates-reformer-agram.com/prijava.html" style="background-color: #c5a880; color: white; padding: 10px 20px; text-decoration: none; border-radius: 20px;">
                Prijavi se ovdje
              </a>
            </p>
          </div>
        `;
        const emailSent = await sendEmail(env, client.email, emailSubject, emailHtml);

        return jsonResponse({ success: true, message: "Nova privremena lozinka je poslana na Vaš e-mail.", emailSent });
      }

      // GET NEWS FEED
      if (request.method === "GET" && url.pathname === "/api/news") {
        const { results } = await env.DB.prepare("SELECT * FROM News ORDER BY created_at DESC").all();
        return jsonResponse({ success: true, news: results });
      }

      // GET INSTAGRAM FEED
      if (request.method === "GET" && url.pathname === "/api/instagram/posts") {
        const { results } = await env.DB.prepare("SELECT * FROM InstagramPosts ORDER BY timestamp DESC LIMIT 6").all();
        return jsonResponse({ success: true, posts: results });
      }


      // --- CLIENT BOOKING ENDPOINTS ---

      // GET AVAILABLE SESSIONS (with client booking status)
      if (request.method === "GET" && url.pathname === "/api/sessions") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const userId = authUser.user_id;

        ctx.waitUntil(checkAndAutoGenerateSchedules(env));
        await autoConfirmBookings(env);

        const nowCroatia = getCroatiaNow();
        const todayStr = formatDate(nowCroatia);
        // Get current time in HH:MM format for filtering past sessions today
        const currentTimeStr = `${String(nowCroatia.getHours()).padStart(2, '0')}:${String(nowCroatia.getMinutes()).padStart(2, '0')}`;
        // Calculate max date: Sunday of the week after next (3 full weeks)
        const currentDayOfWeek = nowCroatia.getDay();
        const daysToSunday = (7 - currentDayOfWeek) % 7;
        const daysToAdd = daysToSunday + 14; // Sunday of the week after next
        const maxDate = new Date(nowCroatia.getTime() + daysToAdd * 24 * 60 * 60 * 1000);
        const maxDateStr = formatDate(maxDate);
        
        // Fetch sessions up to today + 6 days, excluding past sessions from today
        // For future days: show all; for today: only show sessions that haven't started yet
        const { results } = await env.DB.prepare(`
          SELECT s.*, 
                 (SELECT COUNT(*) FROM Bookings b WHERE b.session_id = s.id AND b.status >= 0) as booked_count,
                 (SELECT COUNT(*) FROM Bookings b WHERE b.session_id = s.id AND b.user_id = ? AND b.status >= 0) as user_booked,
                 (SELECT COUNT(*) FROM Waitlists w WHERE w.session_id = s.id AND w.user_id = ?) as user_waitlisted,
                 (SELECT COUNT(*) FROM Waitlists w WHERE w.session_id = s.id) as waitlist_count,
                 (SELECT COUNT(*) FROM Waitlists w WHERE w.session_id = s.id AND w.created_at <= (SELECT w2.created_at FROM Waitlists w2 WHERE w2.session_id = s.id AND w2.user_id = ?)) as user_waitlist_position
          FROM Sessions s
          WHERE s.date <= ?
            AND (s.date > ? OR (s.date = ? AND s.time > ?))
          ORDER BY s.date ASC, s.time ASC
        `).bind(userId, userId, userId, maxDateStr, todayStr, todayStr, currentTimeStr).all();

        return jsonResponse({ success: true, sessions: results });
      }

      // BOOK A SESSION
      if (request.method === "POST" && url.pathname === "/api/book") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const { session_id } = await request.json();
        if (!session_id) {
          return jsonResponse({ success: false, error: "Svi parametri su obavezni." }, 400);
        }
        const user_id = authUser.user_id;

        // 1. Get Client credits and check expiration
        const client = await env.DB.prepare(
          "SELECT username, email, remaining_credits, package_expires, package_name, status FROM Clients WHERE id = ?"
        ).bind(user_id).first();

        if (!client) {
          return jsonResponse({ success: false, error: "Korisnik nije pronađen." }, 404);
        }

        if (client.status === "frozen") {
          return jsonResponse({ success: false, error: "Vaša članarina je trenutno zaleđena. Nije moguće rezervirati nove termine." }, 400);
        }

        if (client.remaining_credits <= 0) {
          return jsonResponse({ success: false, error: "Nemate preostalih treninga (kredita) u paketu." }, 400);
        }

        const todayStr = formatDate(getCroatiaNow());
        if (client.package_expires && client.package_expires < todayStr) {
          return jsonResponse({ success: false, error: `Vaš paket (${client.package_name}) je istekao dana ${client.package_expires}.` }, 400);
        }

        // 2. Check Session capacity and if user is already booked
        const session = await env.DB.prepare("SELECT * FROM Sessions WHERE id = ?").bind(session_id).first();
        if (!session) {
          return jsonResponse({ success: false, error: "Termin nije pronađen." }, 404);
        }

        // Zabrana višekratnog otkazivanja i ponovnog rezerviranja istog termina (maksimalno 2 rezervacije po klijentu za isti termin)
        const bookingAttemptsObj = await env.DB.prepare(
          "SELECT COUNT(*) as count FROM Bookings WHERE session_id = ? AND user_id = ?"
        ).bind(session_id, user_id).first();
        if (bookingAttemptsObj && bookingAttemptsObj.count >= 2) {
          return jsonResponse({ success: false, error: "Nije moguće rezervirati isti termin više od 2 puta (već ste ga rezervirali i otkazali)." }, 400);
        }

        // Check if user already has an active booking on this session's date
        const existingBookingToday = await env.DB.prepare(`
          SELECT b.id FROM Bookings b 
          JOIN Sessions s ON b.session_id = s.id 
          WHERE b.user_id = ? AND s.date = ? AND b.status >= 0
        `).bind(user_id, session.date).first();
        
        if (existingBookingToday) {
          return jsonResponse({ success: false, error: "Već imate rezerviran termin za ovaj dan. Nije moguće rezervirati više termina u istom danu." }, 400);
        }

        const bookingCountObj = await env.DB.prepare(
          "SELECT COUNT(*) as count FROM Bookings WHERE session_id = ? AND status >= 0"
        ).bind(session_id).first();
        const bookedCount = bookingCountObj ? bookingCountObj.count : 0;

        if (bookedCount >= session.capacity) {
          return jsonResponse({ success: false, error: "Termin je već popunjen." }, 400);
        }

        const existingBooking = await env.DB.prepare(
          "SELECT id FROM Bookings WHERE session_id = ? AND user_id = ? AND status >= 0"
        ).bind(session_id, user_id).first();
        if (existingBooking) {
          return jsonResponse({ success: false, error: "Već ste prijavljeni na ovaj termin." }, 400);
        }

        // 3. Make booking & deduct credit
        // We run these as a batch to ensure consistency
        await env.DB.batch([
          env.DB.prepare("INSERT INTO Bookings (session_id, user_id, status) VALUES (?, ?, 0)").bind(session_id, user_id),
          env.DB.prepare("UPDATE Clients SET remaining_credits = remaining_credits - 1 WHERE id = ?").bind(user_id)
        ]);

        const dateStr = session.date.split('-').reverse().join('.') + '.';
        await logActivity(env, `Rezervacija: ${client.username} → ${session.title} (${dateStr}, ${session.time}h)`);

        // Send booking confirmation email with Google Calendar link
        if (client.email) {
          const dateStrFormatted = session.date.split('-').reverse().join('.') + '.';
          const emailSubject = `Potvrda rezervacije: ${session.title}`;
          
          // Generate Google Calendar Link
          const dateFormattedNoDashes = session.date.replace(/-/g, '');
          const timeFormattedNoColons = session.time.replace(/:/g, '');
          const startHour = parseInt(session.time.split(':')[0], 10);
          const startMinute = session.time.split(':')[1];
          const endHour = String(startHour + 1).padStart(2, '0');
          const endTimeFormatted = `${endHour}${startMinute}`;
          
          const googleCalUrl = `https://calendar.google.com/calendar/render?action=TEMPLATE&text=${encodeURIComponent('Agram Pilates - ' + session.title)}&dates=${dateFormattedNoDashes}T${timeFormattedNoColons}00/${dateFormattedNoDashes}T${endTimeFormatted}00&ctz=Europe/Zagreb&details=${encodeURIComponent('Potvrda rezervacije za termin u Agram Pilates studiju.')}`;
          
          const emailHtml = `
            <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5; border: 1px solid #ebdcc5; border-radius: 6px; max-width: 480px; margin: 0 auto;">
              <h2 style="color: #a98e65; margin-top: 0; text-transform: uppercase; font-size: 1.2rem; border-bottom: 1.5px solid #ebdcc5; padding-bottom: 6px;">Uspješna rezervacija termina!</h2>
              <p>Bok <b>${client.username}</b>,</p>
              <p>Potvrđujemo da ste uspješno rezervirali sljedeći termin:</p>
              <table style="border-spacing: 10px; margin-bottom: 20px; font-size: 0.9rem;">
                <tr><td><b>Termin:</b></td><td>${session.title}</td></tr>
                <tr><td><b>Datum i vrijeme:</b></td><td>${dateStrFormatted} u ${session.time}h</td></tr>
                <tr><td><b>Trener:</b></td><td>${session.instructor || 'Adrijana'}</td></tr>
              </table>
              
              <p style="margin-top: 25px; margin-bottom: 25px; text-align: center;">
                <a href="${googleCalUrl}" target="_blank" style="background-color: #c5a880; color: white; padding: 12px 20px; text-decoration: none; border-radius: 20px; font-weight: bold; display: inline-block;">
                  Dodaj svoj termin u google kalendar
                </a>
              </p>
              
              <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 30px;">
              <p style="font-size: 11px; color: #7c7267; text-align: center; margin: 0;">Ova poruka je poslana automatski. Molimo ne odgovarajte na nju.</p>
            </div>
          `;
          ctx.waitUntil(sendEmail(env, client.email, emailSubject, emailHtml));
        }

        // If they had exactly 1 credit remaining, they used their last credit! Send notification email.
        if (client.remaining_credits === 1 && client.email) {
          const emailSubject = "Agram Pilates - Iskoristili ste sve treninge iz paketa";
          const emailHtml = `
            <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5;">
              <h2 style="color: #a98e65;">Svi treninzi su iskorišteni</h2>
              <p>Bok <b>${client.username}</b>,</p>
              <p>Obavještavamo Vas da ste upravo rezervacijom termina <b>'${session.title}'</b> iskoristili zadnji preostali trening iz Vašeg paketa <b>${client.package_name}</b>.</p>
              <p>Kako biste mogli nastaviti s vježbanjem i rezervirati nove termine, molimo Vas da odaberete novi paket unutar aplikacije.</p>
              <p style="margin-top: 30px;">
                <a href="https://pilates-reformer-agram.com/dashboard.html" style="background-color: #c5a880; color: white; padding: 10px 20px; text-decoration: none; border-radius: 20px;">
                  Otvori Profil i odaberi paket
                </a>
              </p>
              <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 30px;">
              <p style="font-size: 11px; color: #7c7267;">Ova poruka je poslana automatski. Molimo ne odgovarajte na nju.</p>
            </div>
          `;
          ctx.waitUntil(sendEmail(env, client.email, emailSubject, emailHtml));
        }

        return jsonResponse({ success: true, message: "Uspješna rezervacija termina!" });
      }

      // CANCEL A BOOKING (12-hour rule)
      if (request.method === "POST" && url.pathname === "/api/cancel-booking") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const { session_id } = await request.json();
        if (!session_id) {
          return jsonResponse({ success: false, error: "Svi parametri su obavezni." }, 400);
        }
        const user_id = authUser.user_id;

        // 1. Check if booking exists
        const booking = await env.DB.prepare(
          "SELECT id, status FROM Bookings WHERE session_id = ? AND user_id = ? AND status >= 0"
        ).bind(session_id, user_id).first();
        if (!booking) {
          return jsonResponse({ success: false, error: "Rezervacija nije pronađena." }, 404);
        }

        // 2. Get session date/time to check 12h limit
        const session = await env.DB.prepare("SELECT date, time FROM Sessions WHERE id = ?").bind(session_id).first();
        if (!session) {
          return jsonResponse({ success: false, error: "Termin nije pronađen." }, 404);
        }

        const nowCroatia = getCroatiaNow();
        const sessionCroatia = new Date(`${session.date}T${session.time}:00`);
        const diffHours = (sessionCroatia.getTime() - nowCroatia.getTime()) / (1000 * 60 * 60);

        let refunded = false;
        let messageText = "";

        if (diffHours >= 12) {
          // In-time cancel: Refund credit but keep row with status = -2
          await env.DB.batch([
            env.DB.prepare("UPDATE Bookings SET status = -2 WHERE session_id = ? AND user_id = ? AND status = 0").bind(session_id, user_id),
            env.DB.prepare("UPDATE Clients SET remaining_credits = remaining_credits + 1 WHERE id = ?").bind(user_id)
          ]);
          refunded = true;
          messageText = "Termin je otkazan. Trening Vam je vraćen na račun. Molimo Vas da rezervirate idući slobodan termin ili nas osobno kontaktirate za dogovor.";
        } else {
          // Late cancel: Delete booking but do NOT refund credit
          await env.DB.prepare("UPDATE Bookings SET status = -1 WHERE session_id = ? AND user_id = ?").bind(session_id, user_id).run();
          refunded = false;
          messageText = "Termin je otkazan manje od 12 sati prije treninga. Kredit se ne vraća (broji se kao iskorišten). Molimo Vas da rezervirate idući slobodan termin ili nas osobno kontaktirate za dogovor.";
        }

        const client = await env.DB.prepare("SELECT username FROM Clients WHERE id = ?").bind(user_id).first();
        if (client) {
          const dateStr = session.date.split('-').reverse().join('.') + '.';
          const cancelType = refunded ? "pravovremeno" : "neopravdano (kasno)";
          await logActivity(env, `Otkazano (${cancelType}): ${client.username} → ${session.title} (${dateStr}, ${session.time}h)`);
        }

        // Notify waitlist when a session spot opens up
        await notifyWaitlist(env, session_id);

        return jsonResponse({ success: true, refunded, message: messageText });
      }

      // JOIN WAITLIST
      if (request.method === "POST" && url.pathname === "/api/waitlist/join") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const { session_id } = await request.json();
        if (!session_id) {
          return jsonResponse({ success: false, error: "Svi parametri su obavezni." }, 400);
        }
        const user_id = authUser.user_id;

        // 1. Check if client exists
        const client = await env.DB.prepare("SELECT username, status FROM Clients WHERE id = ?").bind(user_id).first();
        if (!client) {
          return jsonResponse({ success: false, error: "Korisnik nije pronađen." }, 404);
        }

        if (client.status === "frozen") {
          return jsonResponse({ success: false, error: "Vaša članarina je trenutno zaleđena. Nije moguće prijaviti se na listu čekanja." }, 400);
        }

        // 2. Check if session exists
        const session = await env.DB.prepare("SELECT title, date, time FROM Sessions WHERE id = ?").bind(session_id).first();
        if (!session) {
          return jsonResponse({ success: false, error: "Termin nije pronađen." }, 404);
        }

        // Zabrana višekratnog otkazivanja i ponovnog rezerviranja istog termina (maksimalno 2 rezervacije po klijentu za isti termin)
        const bookingAttemptsObj = await env.DB.prepare(
          "SELECT COUNT(*) as count FROM Bookings WHERE session_id = ? AND user_id = ?"
        ).bind(session_id, user_id).first();
        if (bookingAttemptsObj && bookingAttemptsObj.count >= 2) {
          return jsonResponse({ success: false, error: "Nije moguće prijaviti se na listu čekanja jer ste ovaj termin već rezervirali i otkazali 2 puta." }, 400);
        }

        // 3. Check if user is already booked
        const existingBooking = await env.DB.prepare(
          "SELECT id FROM Bookings WHERE session_id = ? AND user_id = ? AND status >= 0"
        ).bind(session_id, user_id).first();
        if (existingBooking) {
          return jsonResponse({ success: false, error: "Već ste prijavljeni na ovaj termin." }, 400);
        }

        // 4. Check if user already has an active booking on this session's date
        const existingBookingToday = await env.DB.prepare(`
          SELECT b.id FROM Bookings b 
          JOIN Sessions s ON b.session_id = s.id 
          WHERE b.user_id = ? AND s.date = ? AND b.status >= 0
        `).bind(user_id, session.date).first();
        
        if (existingBookingToday) {
          return jsonResponse({ success: false, error: "Već imate rezerviran termin za ovaj dan. Nije moguće biti na listi čekanja za drugi termin istog dana." }, 400);
        }

        // 5. Insert into Waitlists
        try {
          await env.DB.prepare(
            "INSERT INTO Waitlists (session_id, user_id) VALUES (?, ?)"
          ).bind(session_id, user_id).run();

          // Count position on waitlist
          const posObj = await env.DB.prepare(
            "SELECT COUNT(*) as pos FROM Waitlists WHERE session_id = ?"
          ).bind(session_id).first();
          const position = posObj ? posObj.pos : 1;

          const dateStr = session.date.split('-').reverse().join('.') + '.';
          await logActivity(env, `Wait lista: ${client.username} → ${session.title} (${dateStr}, ${session.time}h) [${position}. na listi]`);

          return jsonResponse({ success: true, message: `Uspješno ste se prijavili na listu čekanja! Vi ste ${position}. na listi.`, position });
        } catch (err) {
          if (err.message && err.message.includes("UNIQUE")) {
            return jsonResponse({ success: true, message: "Već ste na listi čekanja za ovaj termin." });
          }
          throw err;
        }
      }

      // LEAVE WAITLIST
      if (request.method === "POST" && url.pathname === "/api/waitlist/leave") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const { session_id } = await request.json();
        if (!session_id) {
          return jsonResponse({ success: false, error: "Svi parametri su obavezni." }, 400);
        }
        const user_id = authUser.user_id;

        const client = await env.DB.prepare("SELECT username FROM Clients WHERE id = ?").bind(user_id).first();
        const session = await env.DB.prepare("SELECT title, date, time FROM Sessions WHERE id = ?").bind(session_id).first();

        await env.DB.prepare(
          "DELETE FROM Waitlists WHERE session_id = ? AND user_id = ?"
        ).bind(session_id, user_id).run();

        if (client && session) {
          const dateStr = session.date.split('-').reverse().join('.') + '.';
          await logActivity(env, `Napustio wait listu: ${client.username} → ${session.title} (${dateStr}, ${session.time}h)`);
        }

        return jsonResponse({ success: true, message: "Uspješno ste se maknuli s liste čekanja." });
      }

      // CLIENT DASHBOARD DATA (Get current bookings and history)
      if (request.method === "GET" && url.pathname === "/api/client/dashboard") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const userId = authUser.user_id;

        await autoConfirmBookings(env);

        const todayStr = formatDate(getCroatiaNow());

        // 1. Upcoming bookings
        const upcomingBookings = await env.DB.prepare(`
          SELECT b.id as booking_id, b.status, s.id as session_id, s.title, s.instructor, s.date, s.time, s.type
          FROM Bookings b
          JOIN Sessions s ON b.session_id = s.id
          WHERE b.user_id = ? AND s.date >= ? AND b.status = 0
          ORDER BY s.date ASC, s.time ASC
        `).bind(userId, todayStr).all();

        // 2. Attendance history (attended or late-cancelled)
        const historyBookings = await env.DB.prepare(`
          SELECT b.id as booking_id, b.status, s.title, s.instructor, s.date, s.time, s.type
          FROM Bookings b
          JOIN Sessions s ON b.session_id = s.id
          WHERE b.user_id = ? AND (s.date < ? OR b.status != 0) AND b.status != -2
          ORDER BY s.date DESC, s.time DESC
          LIMIT 20
        `).bind(userId, todayStr).all();

        const userDetails = await env.DB.prepare(`
          SELECT username, email, package_name, total_credits, remaining_credits, package_expires, must_change_password, questionnaire, status, full_name, first_name, last_name, phone,
                 (SELECT COUNT(*) FROM Bookings b WHERE b.user_id = Clients.id AND b.status = 1) as attended_count
          FROM Clients WHERE id = ?
        `).bind(userId).first();

        // 3.5. Check for pending package requests
        const pendingRequest = await env.DB.prepare(
          "SELECT package_name FROM PackageRequests WHERE user_id = ? AND status = 'pending' LIMIT 1"
        ).bind(userId).first();

        // 4. Notifications
        const notifications = await env.DB.prepare(`
          SELECT id, message, is_read, created_at
          FROM ClientNotifications
          WHERE user_id = ?
          ORDER BY id DESC
          LIMIT 10
        `).bind(userId).all();

        return jsonResponse({
          success: true,
          user: userDetails,
          pending_request: pendingRequest,
          upcoming: upcomingBookings.results,
          history: historyBookings.results,
          notifications: notifications.results
        });
      }

      // CLIENT: MARK NOTIFICATIONS AS READ
      if (request.method === "POST" && url.pathname === "/api/client/notifications/read") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const { notification_ids } = await request.json();
        const user_id = authUser.user_id;

        if (notification_ids && notification_ids.length > 0) {
          const placeholders = notification_ids.map(() => "?").join(",");
          await env.DB.prepare(`
            UPDATE ClientNotifications
            SET is_read = 1
            WHERE user_id = ? AND id IN (${placeholders})
          `).bind(user_id, ...notification_ids).run();
        } else {
          await env.DB.prepare("UPDATE ClientNotifications SET is_read = 1 WHERE user_id = ?").bind(user_id).run();
        }

        return jsonResponse({ success: true });
      }

      // QR CODE CHECK-IN
      if (request.method === "POST" && url.pathname === "/api/check-in") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const user_id = authUser.user_id;

        const nowCroatia = getCroatiaNow();
        const todayStr = formatDate(nowCroatia);
        const currentHour = nowCroatia.getHours();
        const currentMin = nowCroatia.getMinutes();

        // Load username for activity log
        const clientObj = await env.DB.prepare("SELECT username FROM Clients WHERE id = ?").bind(user_id).first();
        const clientName = clientObj ? clientObj.username : `Korisnik ID ${user_id}`;

        // 1. Look for a booking for today
        const bookingsToday = await env.DB.prepare(`
          SELECT b.id as booking_id, b.status, s.id as session_id, s.time, s.title
          FROM Bookings b
          JOIN Sessions s ON b.session_id = s.id
          WHERE b.user_id = ? AND s.date = ? AND b.status = 0
        `).bind(user_id, todayStr).all();

        for (const booking of bookingsToday.results) {
          const [sHour, sMin] = booking.time.split(':').map(Number);
          // Check if session starts within +/- 60 minutes of now
          const diffMinutes = Math.abs((sHour * 60 + sMin) - (currentHour * 60 + currentMin));
          if (diffMinutes <= 60) {
            // Confirm attendance
            await env.DB.prepare("UPDATE Bookings SET status = 1 WHERE id = ?").bind(booking.booking_id).run();
            await logActivity(env, `Check-in: ${clientName} → ${booking.title} (${booking.time}h)`);
            return jsonResponse({ 
              success: true, 
              message: `Uspješna prijava (check-in) na termin: ${booking.title} u ${booking.time}. Dobrodošli u studio Agram!` 
            });
          }
        }

        // 2. If no booking exists, check if there is an active session running now that has spots
        const sessionsToday = await env.DB.prepare(
          "SELECT id, title, time, capacity, type FROM Sessions WHERE date = ?"
        ).bind(todayStr).all();

        for (const session of sessionsToday.results) {
          const [sHour, sMin] = session.time.split(':').map(Number);
          const diffMinutes = Math.abs((sHour * 60 + sMin) - (currentHour * 60 + currentMin));
          
          if (diffMinutes <= 45) { // If starts within 45 min
            // Check capacity
            const countObj = await env.DB.prepare(
              "SELECT COUNT(*) as count FROM Bookings WHERE session_id = ? AND status >= 0"
            ).bind(session.id).first();
            const booked = countObj ? countObj.count : 0;

            if (booked < session.capacity) {
              // Check client credits
              const client = await env.DB.prepare("SELECT username, email, remaining_credits, package_expires, package_name FROM Clients WHERE id = ?").bind(user_id).first();
              if (client && client.remaining_credits > 0 && (!client.package_expires || client.package_expires >= todayStr)) {
                // Book dynamically and check-in
                await env.DB.batch([
                  env.DB.prepare("INSERT INTO Bookings (session_id, user_id, status) VALUES (?, ?, 1)").bind(session.id, user_id),
                  env.DB.prepare("UPDATE Clients SET remaining_credits = remaining_credits - 1 WHERE id = ?").bind(user_id)
                ]);
                await logActivity(env, `Auto check-in: ${clientName} → ${session.title} (${session.time}h)`);

                // If they had exactly 1 credit remaining, they used their last credit! Send notification email.
                if (client.remaining_credits === 1 && client.email) {
                  const emailSubject = "Agram Pilates - Iskoristili ste sve treninge iz paketa";
                  const emailHtml = `
                    <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5;">
                      <h2 style="color: #a98e65;">Svi treninzi su iskorišteni</h2>
                      <p>Bok <b>${client.username}</b>,</p>
                      <p>Obavještavamo Vas da ste upravo automatskom prijavom na termin <b>'${session.title}'</b> iskoristili zadnji preostali trening iz Vašeg paketa <b>${client.package_name}</b>.</p>
                      <p>Kako biste mogli nastaviti s vježbanjem i rezervirati nove termine, molimo Vas da odaberete novi paket unutar aplikacije.</p>
                      <p style="margin-top: 30px;">
                        <a href="https://pilates-reformer-agram.com/dashboard.html" style="background-color: #c5a880; color: white; padding: 10px 20px; text-decoration: none; border-radius: 20px;">
                          Otvori Profil i odaberi paket
                        </a>
                      </p>
                      <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 30px;">
                      <p style="font-size: 11px; color: #7c7267;">Ova poruka je poslana automatski. Molimo ne odgovarajte na nju.</p>
                    </div>
                  `;
                  ctx.waitUntil(sendEmail(env, client.email, emailSubject, emailHtml));
                }

                return jsonResponse({
                  success: true,
                  message: `Automatski ste prijavljeni na slobodni termin: ${session.title} u ${session.time}. Skinut vam je 1 trening.`
                });
              }
            }
          }
        }

        return jsonResponse({
          success: false,
          error: "Nemate rezerviran termin u ovom satu, niti ima trenutno slobodnih grupa za automatsku prijavu."
        }, 400);
      }


      // CLIENT: SAVE HEALTH QUESTIONNAIRE
      if (request.method === "POST" && url.pathname === "/api/client/questionnaire") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const { answers } = await request.json();
        if (!answers) {
          return jsonResponse({ success: false, error: "Nedostaju parametri." }, 400);
        }
        const user_id = authUser.user_id;

        const answersStr = JSON.stringify(answers);
        await env.DB.prepare("UPDATE Clients SET questionnaire = ? WHERE id = ?").bind(answersStr, user_id).run();
        
        // Log activity
        const user = await env.DB.prepare("SELECT username FROM Clients WHERE id = ?").bind(user_id).first();
        if (user) {
          await logActivity(env, `Ispunjen upitnik: ${user.username}`);
        }
        
        return jsonResponse({ success: true, message: "Upitnik uspješno spremljen." });
      }


      // ADMIN ONLY ENDPOINTS PROTECTION
      if (url.pathname.startsWith("/api/admin/")) {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        if (!authUser.is_admin) {
          return jsonResponse({ success: false, error: "Nemate administratorska prava." }, 403);
        }
      }

      // --- ADMIN ONLY ENDPOINTS (Wife's dashboard) ---

      // ADMIN: GET PENDING CLIENTS
      if (request.method === "GET" && url.pathname === "/api/admin/pending-clients") {
        const { results } = await env.DB.prepare(
          "SELECT id, username, email, created_at, full_name, first_name, last_name, phone FROM Clients WHERE status = 'pending' ORDER BY created_at DESC"
        ).all();
        return jsonResponse({ success: true, clients: results });
      }

      // ADMIN: APPROVE CLIENT
      if (request.method === "POST" && url.pathname === "/api/admin/approve-client") {
        const { client_id } = await request.json();
        if (!client_id) {
          return jsonResponse({ success: false, error: "ID klijenta je obavezan." }, 400);
        }

        const client = await env.DB.prepare("SELECT username, email FROM Clients WHERE id = ? AND status = 'pending'").bind(client_id).first();
        if (!client) {
          return jsonResponse({ success: false, error: "Klijent na čekanju nije pronađen." }, 404);
        }

        const tempPass = generateTempPassword();
        const hashedTemp = await hashPassword(tempPass);

        await env.DB.prepare("UPDATE Clients SET status = 'approved', password = ?, must_change_password = 1 WHERE id = ?").bind(hashedTemp, client_id).run();
        await logActivity(env, `Odobrena registracija: ${client.username}`);

        // Slanje maila s privremenom lozinkom
        const emailSubject = "Pilates Reformer Agram - Profil odobren";
        const emailHtml = `
          <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5;">
            <h2 style="color: #a98e65;">Vaš profil je odobren!</h2>
            <p>Dobrodošli u Pilates Reformer studio Agram! Vaš zahtjev za registraciju je odobren. Možete se prijaviti sa sljedećim podacima:</p>
            <table style="border-spacing: 10px;">
              <tr><td><b>Korisničko ime:</b></td><td>${client.username}</td></tr>
              <tr><td><b>Privremena lozinka:</b></td><td><code style="background-color: #eee; padding: 3px 6px; border-radius: 3px;">${tempPass}</code></td></tr>
            </table>
            <p style="margin-top: 20px;">
              Pri prvoj prijavi morat ćete postaviti novu trajnu lozinku i ispuniti kratki zdravstveni upitnik.
            </p>
            <p style="margin-top: 30px;">
              <a href="https://pilates-reformer-agram.com/prijava.html" style="background-color: #c5a880; color: white; padding: 10px 20px; text-decoration: none; border-radius: 20px;">
                Prijavi se ovdje
              </a>
            </p>
          </div>
        `;
        const emailSent = await sendEmail(env, client.email, emailSubject, emailHtml);

        return jsonResponse({ success: true, message: "Klijent je odobren i poslan mu je e-mail s lozinkom.", tempPassword: tempPass, emailSent });
      }

      // ADMIN: REJECT CLIENT
      if (request.method === "POST" && url.pathname === "/api/admin/reject-client") {
        const { client_id } = await request.json();
        if (!client_id) {
          return jsonResponse({ success: false, error: "ID klijenta je obavezan." }, 400);
        }

        const client = await env.DB.prepare("SELECT username FROM Clients WHERE id = ? AND status = 'pending'").bind(client_id).first();
        if (!client) {
          return jsonResponse({ success: false, error: "Klijent na čekanju nije pronađen." }, 404);
        }

        await env.DB.prepare("DELETE FROM Clients WHERE id = ?").bind(client_id).run();
        await logActivity(env, `Odbijena registracija: ${client.username}`);

        return jsonResponse({ success: true, message: "Zahtjev za registraciju je odbačen." });
      }

      // ADMIN: DELETE CLIENT (complete removal of client and all relational data)
      if (request.method === "POST" && url.pathname === "/api/admin/delete-client") {
        const { client_id } = await request.json();
        if (!client_id) {
          return jsonResponse({ success: false, error: "ID klijenta je obavezan." }, 400);
        }

        const client = await env.DB.prepare("SELECT username FROM Clients WHERE id = ?").bind(client_id).first();
        if (!client) {
          return jsonResponse({ success: false, error: "Klijent nije pronađen." }, 404);
        }

        // Batch delete from all relational tables referencing user_id
        await env.DB.batch([
          env.DB.prepare("DELETE FROM Bookings WHERE user_id = ?").bind(client_id),
          env.DB.prepare("DELETE FROM ClientNotifications WHERE user_id = ?").bind(client_id),
          env.DB.prepare("DELETE FROM WorkshopSignups WHERE user_id = ?").bind(client_id),
          env.DB.prepare("DELETE FROM Clients WHERE id = ?").bind(client_id)
        ]);

        await logActivity(env, `Obrisan klijent: ${client.username}`);

        return jsonResponse({ success: true, message: `Klijent '${client.username}' i svi njegovi podaci su obrisani.` });
      }

      // ADMIN: GET LIST OF APPROVED CLIENTS
      if (request.method === "GET" && url.pathname === "/api/admin/clients") {
        const { results } = await env.DB.prepare(`
          SELECT id, username, email, package_name, total_credits, remaining_credits, package_expires, created_at, questionnaire, status, full_name, first_name, last_name, phone,
                 (SELECT COUNT(*) FROM Bookings b WHERE b.user_id = Clients.id AND b.status = 1) as attended_count
          FROM Clients
          WHERE is_admin = 0 AND status IN ('approved', 'frozen')
          ORDER BY COALESCE(full_name, username) ASC
        `).all();

        return jsonResponse({ success: true, clients: results });
      }

      // ADMIN: GET DETAILED BOOKINGS FOR A CLIENT
      if (request.method === "GET" && url.pathname === "/api/admin/client-bookings") {
        const client_id = url.searchParams.get("client_id");
        if (!client_id) {
          return jsonResponse({ success: false, error: "client_id je obavezan." }, 400);
        }

        const { results } = await env.DB.prepare(`
          SELECT b.id as booking_id, b.status, s.title, s.date, s.time
          FROM Bookings b
          JOIN Sessions s ON b.session_id = s.id
          WHERE b.user_id = ? AND b.status >= -1
          ORDER BY s.date DESC, s.time DESC
        `).bind(client_id).all();

        return jsonResponse({ success: true, bookings: results });
      }

      // ADMIN: GET ACTIVITY LOGS
      if (request.method === "GET" && url.pathname === "/api/admin/activity-logs") {
        const { results } = await env.DB.prepare(`
          SELECT id, details, created_at FROM ActivityLogs
          WHERE details LIKE 'Nova registracija%'
             OR details LIKE 'Zahtjev za paket%'
             OR details LIKE 'Otkazano%'
             OR details LIKE 'Admin otkazao%'
          ORDER BY id DESC LIMIT 30
        `).all();
        return jsonResponse({ success: true, logs: results });
      }

      // ADMIN: CREATE CLIENT (with auto email & temp password)
      if (request.method === "POST" && url.pathname === "/api/admin/create-client") {
        const { full_name, username, email, package_name, total_credits, expiration_days } = await request.json();
        
        if (!username || !email) {
          return jsonResponse({ success: false, error: "Korisničko ime i e-mail su obavezni." }, 400);
        }

        const limit = getPackageLimit(package_name);
        if (package_name !== "Nema paketa" && parseInt(total_credits) > limit) {
          return jsonResponse({ success: false, error: `Broj treninga (${total_credits}) ne može biti veći od limita paketa (${limit}).` }, 400);
        }

        // Check if username/email already exists
        const existing = await env.DB.prepare("SELECT id FROM Clients WHERE username = ? OR email = ?").bind(username, email).first();
        if (existing) {
          return jsonResponse({ success: false, error: "Korisnik s tim korisničkim imenom ili e-mailom već postoji." }, 400);
        }

        const tempPass = generateTempPassword();
        const hashedTemp = await hashPassword(tempPass);
        
        // Calculate expiration date
        let expiresStr = null;
        if (expiration_days) {
          const expiresDate = new Date(getCroatiaNow().getTime() + parseInt(expiration_days) * 24 * 60 * 60 * 1000);
          expiresStr = formatDate(expiresDate);
        }

        let firstName = null;
        let lastName = null;
        if (full_name) {
          const nameParts = full_name.trim().split(/\s+/);
          firstName = nameParts[0] || null;
          if (nameParts.length > 1) {
            lastName = nameParts.slice(1).join(" ");
          } else {
            lastName = "";
          }
        }

        // Insert client
        const result = await env.DB.prepare(`
          INSERT INTO Clients (username, email, password, is_admin, must_change_password, package_name, total_credits, remaining_credits, package_expires, full_name, first_name, last_name)
          VALUES (?, ?, ?, 0, 1, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          username, 
          email, 
          hashedTemp, 
          package_name || "Nema paketa", 
          parseInt(total_credits) || 0, 
          parseInt(total_credits) || 0, 
          expiresStr,
          full_name || null,
          firstName,
          lastName
        ).run();

        // Send Email via Resend
        const emailSubject = "Pilates Reformer Agram - Podaci za prijavu";
        const emailHtml = `
          <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5;">
            <h2 style="color: #a98e65;">Dobrodošli u Pilates Reformer studio Agram!</h2>
            <p>Vaš korisnički račun je kreiran. Možete se prijaviti u aplikaciju koristeći sljedeće podatke:</p>
            <table style="border-spacing: 10px;">
              <tr><td><b>Korisničko ime:</b></td><td>${username}</td></tr>
              <tr><td><b>Privremena lozinka:</b></td><td><code style="background-color: #eee; padding: 3px 6px; border-radius: 3px;">${tempPass}</code></td></tr>
            </table>
            <p style="margin-top: 20px;">
              Pri prvoj prijavi od vas će se tražiti da postavite novu, vlastitu lozinku.
            </p>
            <p style="margin-top: 30px;">
              <a href="https://pilates-reformer-agram.com/prijava.html" style="background-color: #c5a880; color: white; padding: 10px 20px; text-decoration: none; border-radius: 20px;">
                Prijavi se ovdje
              </a>
            </p>
            <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 30px;">
            <p style="font-size: 11px; color: #7c7267;">Ova poruka je poslana automatski. Molimo ne odgovarajte na nju.</p>
          </div>
        `;

        const emailSent = await sendEmail(env, email, emailSubject, emailHtml);

        return jsonResponse({
          success: true,
          message: "Klijent je uspješno kreiran!",
          tempPassword: tempPass,
          emailSent: emailSent
        });
      }

      // ADMIN: UPDATE CLIENT PACKAGE / CREDITS
      if (request.method === "POST" && url.pathname === "/api/admin/update-client-credits") {
        const { client_id, package_name, total_credits, remaining_credits, package_expires } = await request.json();
        
        if (!client_id) {
          return jsonResponse({ success: false, error: "Korisnik ID je obavezan." }, 400);
        }

        const limit = getPackageLimit(package_name);
        if (package_name !== "Nema paketa") {
          if (parseInt(total_credits) > limit) {
            return jsonResponse({ success: false, error: `Ukupno treninga (${total_credits}) ne može biti veći od limita paketa (${limit}).` }, 400);
          }
          if (parseInt(remaining_credits) > limit) {
            return jsonResponse({ success: false, error: `Preostalo treninga (${remaining_credits}) ne može biti veći od limita paketa (${limit}).` }, 400);
          }
        }

        await env.DB.prepare(`
          UPDATE Clients 
          SET package_name = ?, total_credits = ?, remaining_credits = ?, package_expires = ?
          WHERE id = ?
        `).bind(
          package_name,
          parseInt(total_credits) || 0,
          parseInt(remaining_credits) || 0,
          package_expires || null,
          client_id
        ).run();

        return jsonResponse({ success: true, message: "Članarina klijenta je uspješno ažurirana!" });
      }

      // ADMIN: MANUAL CHECK-IN (Forgot to scan QR)
      if (request.method === "POST" && url.pathname === "/api/admin/check-in") {
        const { booking_id } = await request.json();
        if (!booking_id) {
          return jsonResponse({ success: false, error: "Booking ID je obavezan." }, 400);
        }

        // Fetch details for logging
        const details = await env.DB.prepare(`
          SELECT c.username, s.title, s.date, s.time
          FROM Bookings b
          JOIN Clients c ON b.user_id = c.id
          JOIN Sessions s ON b.session_id = s.id
          WHERE b.id = ?
        `).bind(booking_id).first();

        // Set status to 1 (attended)
        await env.DB.prepare("UPDATE Bookings SET status = 1 WHERE id = ?").bind(booking_id).run();

        if (details) {
          const dateStr = details.date.split('-').reverse().join('.') + '.';
          await logActivity(env, `Ručni check-in: ${details.username} → ${details.title} (${dateStr} ${details.time}h)`);
        }

        return jsonResponse({ success: true, message: "Dolazak klijenta je uspješno upisan!" });
      }

      // ADMIN: CANCEL BOOKING (with or without refund)
      if (request.method === "POST" && url.pathname === "/api/admin/cancel-booking") {
        const { booking_id, refund } = await request.json();
        if (!booking_id) {
          return jsonResponse({ success: false, error: "Booking ID je obavezan." }, 400);
        }

        // 1. Get booking details to find user_id
        const booking = await env.DB.prepare(
          "SELECT user_id, session_id FROM Bookings WHERE id = ?"
        ).bind(booking_id).first();
        
        if (!booking) {
          return jsonResponse({ success: false, error: "Rezervacija nije pronađena." }, 404);
        }

        // Fetch details for logging before deleting/updating
        const details = await env.DB.prepare(`
          SELECT c.username, s.title, s.date, s.time
          FROM Bookings b
          JOIN Clients c ON b.user_id = c.id
          JOIN Sessions s ON b.session_id = s.id
          WHERE b.id = ?
        `).bind(booking_id).first();

        const dateStr = details ? details.date.split('-').reverse().join('.') + '.' : '';

        if (refund) {
          const msg = details 
            ? `Studio je otkazao Vašu rezervaciju za termin '${details.title}' (${dateStr} u ${details.time}h). Trening Vam je vraćen na račun te možete odabrati novi termin.`
            : `Studio je otkazao Vašu rezervaciju. Trening Vam je vraćen na račun.`;

          // Refund credit: delete booking, add 1 credit, and add client notification
          await env.DB.batch([
            env.DB.prepare("DELETE FROM Bookings WHERE id = ?").bind(booking_id),
            env.DB.prepare("UPDATE Clients SET remaining_credits = remaining_credits + 1 WHERE id = ?").bind(booking.user_id),
            env.DB.prepare("INSERT INTO ClientNotifications (user_id, message) VALUES (?, ?)").bind(booking.user_id, msg)
          ]);
          
          if (details) {
            await logActivity(env, `Admin otkazao (povrat): ${details.username} → ${details.title} (${dateStr} ${details.time}h)`);
          }

          // Notify waitlist when a session spot opens up
          await notifyWaitlist(env, booking.session_id);

          return jsonResponse({ success: true, message: "Rezervacija je uspješno otkazana, a klijentu je vraćen 1 trening na račun!" });
        } else {
          const msg = details
            ? `Studio je otkazao Vašu rezervaciju za termin '${details.title}' (${dateStr} u ${details.time}h) bez povrata treninga na račun.`
            : `Studio je otkazao Vašu rezervaciju bez povrata treninga na račun.`;

          // No refund: set status to -1 (absent) and add client notification
          await env.DB.batch([
            env.DB.prepare("UPDATE Bookings SET status = -1 WHERE id = ?").bind(booking_id),
            env.DB.prepare("INSERT INTO ClientNotifications (user_id, message) VALUES (?, ?)").bind(booking.user_id, msg)
          ]);
          
          if (details) {
            await logActivity(env, `Admin otkazao (bez povrata): ${details.username} → ${details.title} (${dateStr} ${details.time}h)`);
          }

          // Notify waitlist when a session spot opens up
          await notifyWaitlist(env, booking.session_id);

          return jsonResponse({ success: true, message: "Rezervacija je otkazana bez povrata kredita (označeno kao nedolazak)." });
        }
      }

      // ADMIN: GET LIST OF SESSIONS & ATTENDEES FOR A DATE
      if (request.method === "GET" && url.pathname === "/api/admin/sessions-overview") {
        const dateStr = url.searchParams.get("date") || formatDate(getCroatiaNow());
        
        ctx.waitUntil(checkAndAutoGenerateSchedules(env));
        await autoConfirmBookings(env);
        
        const cutoffDate = new Date(getCroatiaNow().getTime() + 12 * 60 * 60 * 1000);
        const cutoffStr = formatLocalDateTimeISO(cutoffDate);
        
        // 1. Get all sessions for this date
        const sessions = await env.DB.prepare(`
          SELECT s.*, 
                 (SELECT COUNT(*) FROM Bookings b WHERE b.session_id = s.id AND b.status >= 0) as booked_count
          FROM Sessions s
          WHERE s.date = ?
          ORDER BY s.time ASC
        `).bind(dateStr).all();

        // 2. Get attendees list for all sessions of this date
        const attendees = await env.DB.prepare(`
          SELECT b.id as booking_id, b.session_id, b.status, c.username, c.email, c.remaining_credits, c.total_credits,
                 (SELECT COUNT(*) FROM Bookings b2 
                  JOIN Sessions s2 ON b2.session_id = s2.id 
                  WHERE b2.user_id = c.id 
                    AND b2.status = 0 
                    AND (s2.date || 'T' || s2.time || ':00') >= ?) as cancelable_count
          FROM Bookings b
          JOIN Clients c ON b.user_id = c.id
          JOIN Sessions s ON b.session_id = s.id
          WHERE s.date = ? AND b.status >= -1
        `).bind(cutoffStr, dateStr).all();

        return jsonResponse({
          success: true,
          sessions: sessions.results,
          attendees: attendees.results
        });
      }

      // ADMIN: CREATE SESSION (Termin)
      if (request.method === "POST" && url.pathname === "/api/admin/create-session") {
        const { title, instructor, date, time, capacity, type } = await request.json();
        
        if (!title || !date || !time) {
          return jsonResponse({ success: false, error: "Naziv, datum i vrijeme su obavezni." }, 400);
        }

        await env.DB.prepare(`
          INSERT INTO Sessions (title, instructor, date, time, capacity, type)
          VALUES (?, ?, ?, ?, ?, ?)
        `).bind(
          title,
          instructor || "Adrijana",
          date,
          time,
          parseInt(capacity) || 4,
          type || "grupni"
        ).run();

        return jsonResponse({ success: true, message: "Novi termin je uspješno dodan u raspored!" });
      }

      // ADMIN: GENERATE WEEKLY SCHEDULE TEMPLATE
      if (request.method === "POST" && url.pathname === "/api/admin/generate-weekly-schedule") {
        const { monday_date } = await request.json();
        if (!monday_date) {
          return jsonResponse({ success: false, error: "Datum ponedjeljka je obavezan." }, 400);
        }

        const start = new Date(monday_date);
        if (isNaN(start.getTime())) {
          return jsonResponse({ success: false, error: "Neispravan format datuma." }, 400);
        }

        const queries = [];
        const instructorName = "Adrijana";

        for (let i = 0; i < 5; i++) {
          const currentDay = new Date(start.getTime() + i * 24 * 60 * 60 * 1000);
          const dateStr = formatDate(currentDay);
          const dayOfWeek = currentDay.getDay(); // 1 = Mon, 2 = Tue, ..., 5 = Fri

          const morningHours = ["07:00", "08:00", "09:00", "10:00"];
          const afternoonHours = ["16:00", "17:00", "18:00", "19:00", "20:00"];
          const allHours = [...morningHours, ...afternoonHours];

          allHours.forEach(time => {
            let type = "grupni";
            let capacity = 4;
            let title = "Grupni trening";

            queries.push(
              env.DB.prepare(`
                INSERT INTO Sessions (title, instructor, date, time, capacity, type)
                SELECT ?, ?, ?, ?, ?, ?
                WHERE NOT EXISTS (
                  SELECT 1 FROM Sessions WHERE date = ? AND time = ?
                )
              `).bind(title, instructorName, dateStr, time, capacity, type, dateStr, time)
            );
          });
        }

        await env.DB.batch(queries);
        return jsonResponse({ success: true, message: "Tjedni raspored je uspješno generiran!" });
      }

      // ADMIN: DELETE SESSION (Refunds credits if cancelled by admin)
      if (request.method === "POST" && url.pathname === "/api/admin/delete-session") {
        const { session_id } = await request.json();
        if (!session_id) {
          return jsonResponse({ success: false, error: "ID termina je obavezan." }, 400);
        }

        // Fetch active bookings for this session to notify clients
        const activeBookings = await env.DB.prepare(`
          SELECT b.user_id, s.title, s.date, s.time
          FROM Bookings b
          JOIN Sessions s ON b.session_id = s.id
          WHERE b.session_id = ? AND b.status >= 0
        `).bind(session_id).all();

        const queries = [];

        // 1. Refund credits to all users registered for this session (status = 0 or 1, not absent -1)
        queries.push(
          env.DB.prepare(`
            UPDATE Clients 
            SET remaining_credits = remaining_credits + 1 
            WHERE id IN (SELECT user_id FROM Bookings WHERE session_id = ? AND status >= 0)
          `).bind(session_id)
        );

        // 2. Insert notifications for each user
        if (activeBookings.results && activeBookings.results.length > 0) {
          activeBookings.results.forEach(booking => {
            const dateStr = booking.date.split('-').reverse().join('.') + '.';
            const msg = `Termin '${booking.title}' (${dateStr} u ${booking.time}h) je otkazan od strane studija. Trening Vam je vraćen na račun te možete odabrati novi termin.`;
            queries.push(
              env.DB.prepare("INSERT INTO ClientNotifications (user_id, message) VALUES (?, ?)").bind(booking.user_id, msg)
            );
          });
        }

        // 3. Delete the session (which will cascade delete bookings)
        queries.push(
          env.DB.prepare("DELETE FROM Sessions WHERE id = ?").bind(session_id)
        );
        queries.push(
          env.DB.prepare("DELETE FROM Waitlists WHERE session_id = ?").bind(session_id)
        );

        await env.DB.batch(queries);

        return jsonResponse({ success: true, message: "Termin je uspješno otkazan i izbrisan, a krediti su vraćeni prijavljenim korisnicima!" });
      }

      // ADMIN: CHANGE SESSION TYPE
      if (request.method === "POST" && url.pathname === "/api/admin/change-session-type") {
        const { session_id, new_type } = await request.json();
        
        if (!session_id || !new_type) {
          return jsonResponse({ success: false, error: "ID termina i novi tip su obavezni." }, 400);
        }

        const validTypes = ["grupni", "poluindividualni", "privatni"];
        if (!validTypes.includes(new_type)) {
          return jsonResponse({ success: false, error: "Neispravan tip treninga." }, 400);
        }

        const session = await env.DB.prepare("SELECT * FROM Sessions WHERE id = ?").bind(session_id).first();
        if (!session) {
          return jsonResponse({ success: false, error: "Termin nije pronađen." }, 404);
        }

        // Provjeri ima li aktivnih rezervacija
        const activeBookings = await env.DB.prepare(
          "SELECT COUNT(*) as count FROM Bookings WHERE session_id = ? AND status >= 0"
        ).bind(session_id).first();

        if (activeBookings && activeBookings.count > 0) {
          return jsonResponse({
            success: false,
            error: "Nije moguće promijeniti tip treninga jer u ovom terminu već postoje prijavljeni klijenti. Molimo Vas da prvo ručno otkažete ili prebacite klijente u neki drugi termin."
          }, 400);
        }

        let newCapacity = 4;
        let newTitle = "Grupni trening";

        if (new_type === "poluindividualni") {
          newCapacity = 2;
          newTitle = "Poluindividualni trening";
        } else if (new_type === "privatni") {
          newCapacity = 1;
          newTitle = "Privatni trening";
        }

        await env.DB.prepare(
          "UPDATE Sessions SET type = ?, capacity = ?, title = ? WHERE id = ?"
        ).bind(new_type, newCapacity, newTitle, session_id).run();

        await logActivity(env, `Promjena tipa: ${session.type} → ${new_type} (${newTitle}, kap. ${newCapacity})`);

        return jsonResponse({ success: true, message: "Tip termina je uspješno promijenjen!" });
      }

      // ADMIN: CREATE NEWS OR WORKSHOP
      if (request.method === "POST" && url.pathname === "/api/admin/create-news") {
        const { title, content, image_url, is_workshop } = await request.json();
        
        if (!title || !content) {
          return jsonResponse({ success: false, error: "Naslov i sadržaj su obavezni." }, 400);
        }

        await env.DB.prepare(`
          INSERT INTO News (title, content, image_url, is_workshop)
          VALUES (?, ?, ?, ?)
        `).bind(
          title,
          content,
          image_url || null,
          parseInt(is_workshop) || 0
        ).run();

        return jsonResponse({ success: true, message: "Obavijest/radionica je uspješno objavljena!" });
      }

      // ADMIN: SEND DAILY REPORT EMAIL ON DEMAND
      if (request.method === "POST" && url.pathname === "/api/admin/send-daily-report") {
        const authUser = await getAuthUser(request, env);
        if (!authUser || authUser.is_admin !== 1) {
          return jsonResponse({ success: false, error: "Nemate administratorska prava." }, 403);
        }

        const { date } = await request.json();
        const dateStr = date || formatDate(getCroatiaNow());
        
        const success = await sendDailyReportEmail(env, dateStr);
        if (success) {
          return jsonResponse({ success: true, message: `Dnevno izvješće za ${dateStr.split('-').reverse().join('.')}. je poslano na e-mail.` });
        } else {
          return jsonResponse({ success: false, error: "Greška pri slanju e-maila." }, 500);
        }
      }

      // ADMIN: MANUALLY BOOK CLIENT TO SESSION
      if (request.method === "POST" && url.pathname === "/api/admin/book-client-manual") {
        const { session_id, client_id } = await request.json();
        
        if (!session_id || !client_id) {
          return jsonResponse({ success: false, error: "Svi parametri su obavezni (session_id, client_id)." }, 400);
        }

        // 1. Get Client credits and check expiration
        const client = await env.DB.prepare(
          "SELECT id, username, email, remaining_credits, package_expires, package_name, status FROM Clients WHERE id = ?"
        ).bind(client_id).first();

        if (!client) {
          return jsonResponse({ success: false, error: "Klijent nije pronađen." }, 404);
        }

        if (client.status === "frozen") {
          return jsonResponse({ success: false, error: "Klijentova članarina je zaleđena. Nije moguće rezervirati termine." }, 400);
        }

        // Check if client has remaining credits
        if (client.remaining_credits <= 0) {
          return jsonResponse({ success: false, error: "Klijent nema preostalih treninga (kredita) u paketu." }, 400);
        }

        const todayStr = formatDate(getCroatiaNow());
        if (client.package_expires && client.package_expires < todayStr) {
          return jsonResponse({ success: false, error: `Klijentov paket (${client.package_name}) je istekao dana ${client.package_expires.split('-').reverse().join('.')}.` }, 400);
        }

        // 2. Check Session capacity and if client is already booked
        const session = await env.DB.prepare("SELECT * FROM Sessions WHERE id = ?").bind(session_id).first();
        if (!session) {
          return jsonResponse({ success: false, error: "Termin nije pronađen." }, 404);
        }

        // Check if user already has an active booking on this session's date
        const existingBookingToday = await env.DB.prepare(`
          SELECT b.id FROM Bookings b 
          JOIN Sessions s ON b.session_id = s.id 
          WHERE b.user_id = ? AND s.date = ? AND b.status >= 0
        `).bind(client_id, session.date).first();
        
        if (existingBookingToday) {
          return jsonResponse({ success: false, error: "Klijent već ima rezerviran termin za ovaj dan." }, 400);
        }

        const bookingCountObj = await env.DB.prepare(
          "SELECT COUNT(*) as count FROM Bookings WHERE session_id = ? AND status >= 0"
        ).bind(session_id).first();
        const bookedCount = bookingCountObj ? bookingCountObj.count : 0;

        if (bookedCount >= session.capacity) {
          return jsonResponse({ success: false, error: "Termin je već popunjen." }, 400);
        }

        const existingBooking = await env.DB.prepare(
          "SELECT id FROM Bookings WHERE session_id = ? AND user_id = ? AND status >= 0"
        ).bind(session_id, client_id).first();
        if (existingBooking) {
          return jsonResponse({ success: false, error: "Klijent je već prijavljen na ovaj termin." }, 400);
        }

        // 3. Make booking, deduct credit, and add client notification
        const dateFormatted = session.date.split('-').reverse().join('.') + '.';
        const notificationMsg = `Studio Vam je rezervirao termin '${session.title}' dana ${dateFormatted} u ${session.time}h.`;

        await env.DB.batch([
          env.DB.prepare("INSERT INTO Bookings (session_id, user_id, status) VALUES (?, ?, 0)").bind(session_id, client_id),
          env.DB.prepare("UPDATE Clients SET remaining_credits = remaining_credits - 1 WHERE id = ?").bind(client_id),
          env.DB.prepare("INSERT INTO ClientNotifications (user_id, message) VALUES (?, ?)").bind(client_id, notificationMsg)
        ]);

        await logActivity(env, `Admin rezervacija: ${client.username} → ${session.title} (${dateFormatted}, ${session.time}h)`);

        // If they had exactly 1 credit remaining, they used their last credit! Send notification email.
        if (client.remaining_credits === 1 && client.email) {
          const emailSubject = "Agram Pilates - Iskoristili ste sve treninge iz paketa";
          const emailHtml = `
            <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5;">
              <h2 style="color: #a98e65;">Svi treninzi su iskorišteni</h2>
              <p>Bok <b>${client.username}</b>,</p>
              <p>Obavještavamo Vas da je studio upravo rezervirao termin <b>'${session.title}'</b> za Vas čime ste iskoristili zadnji preostali trening iz Vašeg paketa <b>${client.package_name}</b>.</p>
              <p>Kako biste mogli nastaviti s vježbanjem i rezervirati nove termine, molimo Vas da odaberete novi paket unutar aplikacije.</p>
              <p style="margin-top: 30px;">
                <a href="https://pilates-reformer-agram.com/dashboard.html" style="background-color: #c5a880; color: white; padding: 10px 20px; text-decoration: none; border-radius: 20px;">
                  Otvori Profil i odaberi paket
                </a>
              </p>
              <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 30px;">
              <p style="font-size: 11px; color: #7c7267;">Ova poruka je poslana automatski. Molimo ne odgovarajte na nju.</p>
            </div>
          `;
          ctx.waitUntil(sendEmail(env, client.email, emailSubject, emailHtml));
        }

        return jsonResponse({ success: true, message: "Rezervacija je uspješno kreirana od strane administratora!" });
      }

      // ADMIN: GET INSTAGRAM CONFIG STATUS
      if (request.method === "GET" && url.pathname === "/api/admin/instagram/status") {
        const tokenObj = await env.DB.prepare("SELECT value FROM Settings WHERE key = 'instagram_access_token'").first();
        const lastSyncObj = await env.DB.prepare("SELECT value FROM Settings WHERE key = 'instagram_last_synced_at'").first();
        const tokenUpdatedObj = await env.DB.prepare("SELECT value FROM Settings WHERE key = 'instagram_token_updated_at'").first();
        
        return jsonResponse({
          success: true,
          isConfigured: !!(tokenObj && tokenObj.value),
          lastSyncedAt: lastSyncObj ? lastSyncObj.value : null,
          tokenUpdatedAt: tokenUpdatedObj ? tokenUpdatedObj.value : null
        });
      }

      // ADMIN: SET INSTAGRAM ACCESS TOKEN
      if (request.method === "POST" && url.pathname === "/api/admin/instagram/token") {
        const { token } = await request.json();
        if (!token) {
          return jsonResponse({ success: false, error: "Pristupni token je obavezan." }, 400);
        }

        const croatiaNow = getCroatiaNow();
        const nowStr = croatiaNow.toISOString().replace('T', ' ').substring(0, 19);

        // Batch save token and mark update time
        await env.DB.batch([
          env.DB.prepare("INSERT OR REPLACE INTO Settings (key, value) VALUES ('instagram_access_token', ?)").bind(token),
          env.DB.prepare("INSERT OR REPLACE INTO Settings (key, value) VALUES ('instagram_token_updated_at', ?)").bind(nowStr)
        ]);

        await logActivity(env, "Ažuriran Instagram token");

        // Pokreni odmah prvu sinkronizaciju objava
        const syncSuccess = await syncInstagramFeed(env);

        return jsonResponse({ 
          success: true, 
          message: "Instagram token je uspješno spremljen!",
          syncSuccess
        });
      }

      // ADMIN: MANUALLY SYNC INSTAGRAM FEED
      if (request.method === "POST" && url.pathname === "/api/admin/instagram/sync") {
        const syncSuccess = await syncInstagramFeed(env);
        if (!syncSuccess) {
          return jsonResponse({ success: false, error: "Neuspješna sinkronizacija. Provjerite ispravnost Instagram tokena." }, 500);
        }

        const { results } = await env.DB.prepare("SELECT * FROM InstagramPosts ORDER BY timestamp DESC LIMIT 6").all();
        return jsonResponse({ success: true, message: "Sinkronizacija uspješna!", posts: results });
      }

      // CLIENT: REQUEST NEW PACKAGE
      if (request.method === "POST" && url.pathname === "/api/client/request-package") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const { package_name } = await request.json();
        if (!package_name) {
          return jsonResponse({ success: false, error: "Nedostaju parametri." }, 400);
        }
        const user_id = authUser.user_id;

        const client = await env.DB.prepare("SELECT username, email, remaining_credits, package_expires, package_name FROM Clients WHERE id = ?").bind(user_id).first();
        if (!client) {
          return jsonResponse({ success: false, error: "Korisnik nije pronađen." }, 404);
        }

        const todayStr = formatDate(getCroatiaNow());
        const isExpired = client.package_expires && client.package_expires < todayStr;
        const hasNoPackage = !client.package_name || client.package_name === "Nema paketa" || client.package_name === "Nema aktivnog paketa";

        if (client.remaining_credits > 0 && !isExpired && !hasNoPackage) {
          return jsonResponse({ success: false, error: "Nije moguće zatražiti novi paket dok ne iskoristite sve treninge iz postojećeg." }, 400);
        }

        const activeRequest = await env.DB.prepare("SELECT id FROM PackageRequests WHERE user_id = ? AND status = 'pending'").bind(user_id).first();
        if (activeRequest) {
          return jsonResponse({ success: false, error: "Već imate aktivan zahtjev za paket na čekanju." }, 400);
        }

        // Save request to DB
        await env.DB.prepare("INSERT INTO PackageRequests (user_id, package_name, status) VALUES (?, ?, 'pending')").bind(user_id, package_name).run();

        // Log activity
        await logActivity(env, `Zahtjev za paket: ${client.username} → ${package_name}`);

        // Send email to admin
        const adminEmail = "adrijana.kontek@gmail.com";
        const subject = `Agram Pilates - Zahtjev za paket: ${client.username}`;
        const htmlContent = `
          <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5;">
            <h2 style="color: #a98e65;">Zahtjev za aktivaciju paketa</h2>
            <p>Klijent <b>${client.username}</b> (e-mail: ${client.email}) je zatražio aktivaciju sljedećeg paketa:</p>
            <p style="font-size: 1.2rem; background-color: #f5eedf; padding: 15px; border-radius: 8px; border: 1px solid #ebdcc5; font-weight: bold; color: #2c251e;">
              ${package_name}
            </p>
            <p style="margin-top: 20px;">
              Molimo Vas da se prijavite u <a href="https://pilates-reformer-agram.com/admin.html">Admin panel</a>, kako biste odobrili ili odbili ovaj zahtjev.
            </p>
          </div>
        `;
        ctx.waitUntil(sendEmail(env, adminEmail, subject, htmlContent));

        return jsonResponse({ success: true, message: `Zahtjev za paket '${package_name}' je uspješno poslan! Paket će biti aktiviran nakon što ga administrator odobri.` });
      }

      // ADMIN: TOGGLE FREEZE CLIENT
      if (request.method === "POST" && url.pathname === "/api/admin/toggle-freeze") {
        const { client_id } = await request.json();
        if (!client_id) {
          return jsonResponse({ success: false, error: "ID klijenta je obavezan." }, 400);
        }

        const client = await env.DB.prepare("SELECT username, status FROM Clients WHERE id = ?").bind(client_id).first();
        if (!client) {
          return jsonResponse({ success: false, error: "Klijent nije pronađen." }, 404);
        }

        let newStatus = "approved";
        let actionMsg = "";
        let respMsg = "";

        if (client.status === "frozen") {
          newStatus = "approved";
          actionMsg = `Admin je odmrznuo račun klijentu '${client.username}'.`;
          respMsg = `Klijent '${client.username}' je uspješno odmrznut.`;
        } else {
          newStatus = "frozen";
          actionMsg = `Admin je zaledio račun klijentu '${client.username}'.`;
          respMsg = `Klijent '${client.username}' je uspješno zaleđen.`;
        }

        await env.DB.prepare("UPDATE Clients SET status = ? WHERE id = ?").bind(newStatus, client_id).run();
        await logActivity(env, actionMsg);

        return jsonResponse({ success: true, message: respMsg, newStatus });
      }

      // ADMIN: GET PENDING PACKAGE REQUESTS
      if (request.method === "GET" && url.pathname === "/api/admin/package-requests") {
        const { results } = await env.DB.prepare(`
          SELECT pr.id as request_id, pr.package_name, pr.created_at, pr.status, c.id as user_id, c.username, c.email, c.full_name
          FROM PackageRequests pr
          JOIN Clients c ON pr.user_id = c.id
          WHERE pr.status = 'pending'
          ORDER BY pr.created_at DESC
        `).all();
        return jsonResponse({ success: true, requests: results });
      }

      // ADMIN: APPROVE PACKAGE REQUEST
      if (request.method === "POST" && url.pathname === "/api/admin/approve-package-request") {
        const { request_id } = await request.json();
        if (!request_id) {
          return jsonResponse({ success: false, error: "ID zahtjeva je obavezan." }, 400);
        }

        const reqObj = await env.DB.prepare("SELECT user_id, package_name FROM PackageRequests WHERE id = ? AND status = 'pending'").bind(request_id).first();
        if (!reqObj) {
          return jsonResponse({ success: false, error: "Zahtjev nije pronađen ili je već obrađen." }, 404);
        }

        const { user_id, package_name } = reqObj;
        const client = await env.DB.prepare("SELECT username, email FROM Clients WHERE id = ?").bind(user_id).first();
        if (!client) {
          return jsonResponse({ success: false, error: "Klijent nije pronađen." }, 404);
        }

        const limit = getPackageLimit(package_name);
        const expiresDate = new Date(getCroatiaNow().getTime() + 30 * 24 * 60 * 60 * 1000);
        const expiresStr = formatDate(expiresDate);

        // Approve: update client credits, mark request as approved, notify client
        const msg = `Vaš zahtjev za aktivaciju paketa '${package_name}' je odobren! Paket je aktiviran.`;
        
        await env.DB.batch([
          env.DB.prepare("UPDATE Clients SET package_name = ?, total_credits = ?, remaining_credits = ?, package_expires = ? WHERE id = ?")
            .bind(package_name, limit, limit, expiresStr, user_id),
          env.DB.prepare("UPDATE PackageRequests SET status = 'approved' WHERE id = ?")
            .bind(request_id),
          env.DB.prepare("INSERT INTO ClientNotifications (user_id, message) VALUES (?, ?)")
            .bind(user_id, msg)
        ]);

        await logActivity(env, `Odobren paket: ${client.username} → ${package_name}`);

        // Send confirmation email to client
        const emailSubject = "Agram Pilates - Paket aktiviran";
        const emailHtml = `
          <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5;">
            <h2 style="color: #a98e65;">Paket je uspješno aktiviran!</h2>
            <p>Bok <b>${client.username}</b>,</p>
            <p>Obavještavamo Vas da je Vaš zahtjev odobren te je paket <b>'${package_name}'</b> (s ${limit} treninga) sada aktivan na Vašem profilu.</p>
            <p>Članarina vrijedi do <b>${expiresStr.split('-').reverse().join('.')}.</b></p>
            <p style="margin-top: 30px;">
              <a href="https://pilates-reformer-agram.com/dashboard.html" style="background-color: #c5a880; color: white; padding: 10px 20px; text-decoration: none; border-radius: 20px;">
                Otvori raspored i rezerviraj termin
              </a>
            </p>
          </div>
        `;
        ctx.waitUntil(sendEmail(env, client.email, emailSubject, emailHtml));

        return jsonResponse({ success: true, message: "Zahtjev je odobren i paket je aktiviran!" });
      }

      // ADMIN: REJECT PACKAGE REQUEST
      if (request.method === "POST" && url.pathname === "/api/admin/reject-package-request") {
        const { request_id } = await request.json();
        if (!request_id) {
          return jsonResponse({ success: false, error: "ID zahtjeva je obavezan." }, 400);
        }

        const reqObj = await env.DB.prepare("SELECT user_id, package_name FROM PackageRequests WHERE id = ? AND status = 'pending'").bind(request_id).first();
        if (!reqObj) {
          return jsonResponse({ success: false, error: "Zahtjev nije pronađen ili je već obrađen." }, 404);
        }

        const { user_id, package_name } = reqObj;
        const client = await env.DB.prepare("SELECT username FROM Clients WHERE id = ?").bind(user_id).first();
        
        const msg = `Vaš zahtjev za aktivaciju paketa '${package_name}' je odbijen. Molimo kontaktirajte studio za detalje.`;

        await env.DB.batch([
          env.DB.prepare("UPDATE PackageRequests SET status = 'rejected' WHERE id = ?").bind(request_id),
          env.DB.prepare("INSERT INTO ClientNotifications (user_id, message) VALUES (?, ?)").bind(user_id, msg)
        ]);

        if (client) {
          await logActivity(env, `Odbijen paket: ${client.username} → ${package_name}`);
        }

        return jsonResponse({ success: true, message: "Zahtjev je odbijen." });
      }

      // Fallback
      return jsonResponse({ success: false, error: "Stranica nije pronađena (404)." }, 404);

    } catch (e) {
      console.error("Worker error:", e);
      return jsonResponse({ success: false, error: "Interna pogreška poslužitelja: " + e.message }, 500);
    }
  },
  async scheduled(event, env, ctx) {
    const promises = [];
    
    // 1. Instagram Feed Sync: runs on 12-hour schedule
    if (!event.cron || event.cron === "0 */12 * * *") {
      promises.push(syncInstagramFeed(env));
    }

    // 1.5. Daily Booking Reminders: runs on 12-hour schedule as well
    if (!event.cron || event.cron === "0 */12 * * *") {
      promises.push(sendBookingReminders(env));
    }

    // 1.6. Auto generate weekly schedules: runs on 12-hour schedule as well
    if (!event.cron || event.cron === "0 */12 * * *") {
      promises.push(checkAndAutoGenerateSchedules(env));
    }
    
    // 2. Weekly Report Email: runs automatically on Fridays in the evening
    if (!event.cron || event.cron === "15 20,21 * * 5") {
      const croatiaNow = getCroatiaNow();
      // Only execute if it's Friday and local time is 22:15 (hour 22), or if running locally/tests without cron property
      if ((croatiaNow.getDay() === 5 && croatiaNow.getHours() === 22) || !event.cron) {
        promises.push(sendWeeklyReportEmail(env));
      }
    }
    
    if (promises.length > 0) {
      ctx.waitUntil(Promise.all(promises));
    }
  }
};