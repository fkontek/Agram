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

// Notify waitlist when a session spot opens up
async function notifyWaitlist(env, sessionId) {
  try {
    // 1. Get session details
    const session = await env.DB.prepare("SELECT title, date, time FROM Sessions WHERE id = ?").bind(sessionId).first();
    if (!session) return;

    // 2. Find all waitlisted users
    const waitlisted = await env.DB.prepare(`
      SELECT w.user_id, c.username, c.email
      FROM Waitlists w
      JOIN Clients c ON w.user_id = c.id
      WHERE w.session_id = ?
    `).bind(sessionId).all();

    if (!waitlisted.results || waitlisted.results.length === 0) {
      return;
    }

    const dateStr = session.date.split('-').reverse().join('.') + '.';
    const subject = `Slobodan termin: ${session.title}`;
    
    const emailContent = `
      <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5;">
        <h2 style="color: #a98e65;">Oslobodilo se mjesto!</h2>
        <p>Obavještavamo Vas da se oslobodilo mjesto za termin na koji ste bili prijavljeni na listi čekanja:</p>
        <table style="border-spacing: 10px;">
          <tr><td><b>Termin:</b></td><td>${session.title}</td></tr>
          <tr><td><b>Datum i vrijeme:</b></td><td>${dateStr} u ${session.time}h</td></tr>
        </table>
        <p style="margin-top: 20px;">
          Termin je sada otvoren za rezervaciju svim klijentima. Ako i dalje želite sudjelovati, prijavite se što prije putem aplikacije jer se mjesta popunjavaju po principu tko prvi rezervira.
        </p>
        <p style="margin-top: 30px;">
          <a href="https://pilates-reformer-agram.com/dashboard.html" style="background-color: #c5a880; color: white; padding: 10px 20px; text-decoration: none; border-radius: 20px;">
            Rezerviraj termin
          </a>
        </p>
        <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 30px;">
        <p style="font-size: 11px; color: #7c7267;">Ova poruka je poslana automatski klijentima na listi čekanja.</p>
      </div>
    `;

    const notificationsQueries = [];
    
    // Send emails and build batch queries for in-app notifications
    for (const user of waitlisted.results) {
      // Send email
      await sendEmail(env, user.email, subject, emailContent);
      
      // Build query for in-app notification
      const inAppMsg = `Oslobodilo se mjesto za termin '${session.title}' (${dateStr} u ${session.time}h) za koji ste bili na listi čekanja. Rezervirajte ga odmah!`;
      notificationsQueries.push(
        env.DB.prepare("INSERT INTO ClientNotifications (user_id, message) VALUES (?, ?)").bind(user.user_id, inAppMsg)
      );
    }

    // 3. Delete the waitlist for this session
    notificationsQueries.push(
      env.DB.prepare("DELETE FROM Waitlists WHERE session_id = ?").bind(sessionId)
    );

    // Run in-app notifications and delete waitlist in a batch
    await env.DB.batch(notificationsQueries);
    
    await logActivity(env, `Poslane obavijesti za ${waitlisted.results.length} klijenta na listi čekanja za termin '${session.title}' (${dateStr} u ${session.time}h).`);
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
          await logActivity(env, `Sustav je automatski zabilježio dolazak (check-in) klijentu '${b.username}' jer je preostalo manje od 12 sati do treninga.`);
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
          "SELECT id, username, email, is_admin, must_change_password, package_name, total_credits, remaining_credits, package_expires, status, questionnaire, full_name FROM Clients WHERE (username = ? OR email = ?) AND password = ?"
        ).bind(username, username, hashedPassword).first();

        if (!user) {
          return jsonResponse({ success: false, error: "Pogrešno korisničko ime/e-mail ili lozinka." }, 401);
        }

        if (user.status === "pending") {
          return jsonResponse({ success: false, error: "Vaš profil još nije odobren od strane administratora." }, 403);
        }

        return jsonResponse({ success: true, user });
      }

      // REGISTER (Public registration, status 'pending' awaiting admin approval)
      if (request.method === "POST" && url.pathname === "/api/register") {
        const { full_name, username, email } = await request.json();
        
        if (!username || !email) {
          return jsonResponse({ success: false, error: "Korisničko ime i e-mail su obavezni." }, 400);
        }

        // Check if username/email already exists
        const existing = await env.DB.prepare("SELECT id FROM Clients WHERE username = ? OR email = ?").bind(username, email).first();
        if (existing) {
          return jsonResponse({ success: false, error: "Korisnik s tim korisničkim imenom ili e-mailom već postoji." }, 400);
        }

        // Insert client with 'pending' status, 'PENDING' password, null questionnaire, and full_name
        await env.DB.prepare(`
          INSERT INTO Clients (username, email, password, is_admin, must_change_password, package_name, total_credits, remaining_credits, package_expires, status, questionnaire, full_name)
          VALUES (?, ?, 'PENDING', 0, 1, 'Nema aktivnog paketa', 0, 0, NULL, 'pending', NULL, ?)
        `).bind(username, email, full_name || null).run();

        await logActivity(env, `Novi klijent '${full_name || username}' je poslao zahtjev za registraciju.`);

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

        await logActivity(env, `Klijent '${client.username}' je zatražio ponovno postavljanje lozinke (zaboravljena lozinka).`);

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
        const userId = url.searchParams.get("user_id");
        if (!userId) {
          return jsonResponse({ success: false, error: "Korisnik ID je obavezan." }, 400);
        }

        await autoConfirmBookings(env);

        const nowCroatia = getCroatiaNow();
        const todayStr = formatDate(nowCroatia);
        // Get current time in HH:MM format for filtering past sessions today
        const currentTimeStr = `${String(nowCroatia.getHours()).padStart(2, '0')}:${String(nowCroatia.getMinutes()).padStart(2, '0')}`;
        // Calculate max date: today + 6 days (rolling 7 days total)
        const maxDate = new Date(nowCroatia.getTime() + 6 * 24 * 60 * 60 * 1000);
        const maxDateStr = formatDate(maxDate);
        
        // Fetch sessions up to today + 6 days, excluding past sessions from today
        // For future days: show all; for today: only show sessions that haven't started yet
        const { results } = await env.DB.prepare(`
          SELECT s.*, 
                 (SELECT COUNT(*) FROM Bookings b WHERE b.session_id = s.id AND b.status >= 0) as booked_count,
                 (SELECT COUNT(*) FROM Bookings b WHERE b.session_id = s.id AND b.user_id = ? AND b.status >= 0) as user_booked,
                 (SELECT COUNT(*) FROM Waitlists w WHERE w.session_id = s.id AND w.user_id = ?) as user_waitlisted
          FROM Sessions s
          WHERE s.date <= ?
            AND (s.date > ? OR (s.date = ? AND s.time > ?))
          ORDER BY s.date ASC, s.time ASC
        `).bind(userId, userId, maxDateStr, todayStr, todayStr, currentTimeStr).all();

        return jsonResponse({ success: true, sessions: results });
      }

      // BOOK A SESSION
      if (request.method === "POST" && url.pathname === "/api/book") {
        const { user_id, session_id } = await request.json();
        if (!user_id || !session_id) {
          return jsonResponse({ success: false, error: "Svi parametri su obavezni." }, 400);
        }

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
        await logActivity(env, `Klijent '${client.username}' je rezervirao termin '${session.title}' (${dateStr} u ${session.time}h).`);

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
        const { user_id, session_id } = await request.json();
        if (!user_id || !session_id) {
          return jsonResponse({ success: false, error: "Svi parametri su obavezni." }, 400);
        }

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
          // In-time cancel: Refund credit
          await env.DB.batch([
            env.DB.prepare("DELETE FROM Bookings WHERE session_id = ? AND user_id = ?").bind(session_id, user_id),
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
          await logActivity(env, `Klijent '${client.username}' je ${cancelType} otkazao termin '${session.title}' (${dateStr} u ${session.time}h).`);
        }

        // Notify waitlist when a session spot opens up
        await notifyWaitlist(env, session_id);

        return jsonResponse({ success: true, refunded, message: messageText });
      }

      // JOIN WAITLIST
      if (request.method === "POST" && url.pathname === "/api/waitlist/join") {
        const { user_id, session_id } = await request.json();
        if (!user_id || !session_id) {
          return jsonResponse({ success: false, error: "Svi parametri su obavezni." }, 400);
        }

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

          const dateStr = session.date.split('-').reverse().join('.') + '.';
          await logActivity(env, `Klijent '${client.username}' se prijavio na listu čekanja za termin '${session.title}' (${dateStr} u ${session.time}h).`);

          return jsonResponse({ success: true, message: "Uspješno ste se prijavili na listu čekanja!" });
        } catch (err) {
          if (err.message && err.message.includes("UNIQUE")) {
            return jsonResponse({ success: true, message: "Već ste na listi čekanja za ovaj termin." });
          }
          throw err;
        }
      }

      // LEAVE WAITLIST
      if (request.method === "POST" && url.pathname === "/api/waitlist/leave") {
        const { user_id, session_id } = await request.json();
        if (!user_id || !session_id) {
          return jsonResponse({ success: false, error: "Svi parametri su obavezni." }, 400);
        }

        const client = await env.DB.prepare("SELECT username FROM Clients WHERE id = ?").bind(user_id).first();
        const session = await env.DB.prepare("SELECT title, date, time FROM Sessions WHERE id = ?").bind(session_id).first();

        await env.DB.prepare(
          "DELETE FROM Waitlists WHERE session_id = ? AND user_id = ?"
        ).bind(session_id, user_id).run();

        if (client && session) {
          const dateStr = session.date.split('-').reverse().join('.') + '.';
          await logActivity(env, `Klijent '${client.username}' se maknuo s liste čekanja za termin '${session.title}' (${dateStr} u ${session.time}h).`);
        }

        return jsonResponse({ success: true, message: "Uspješno ste se maknuli s liste čekanja." });
      }

      // CLIENT DASHBOARD DATA (Get current bookings and history)
      if (request.method === "GET" && url.pathname === "/api/client/dashboard") {
        const userId = url.searchParams.get("user_id");
        if (!userId) {
          return jsonResponse({ success: false, error: "Korisnik ID je obavezan." }, 400);
        }

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
          WHERE b.user_id = ? AND (s.date < ? OR b.status != 0)
          ORDER BY s.date DESC, s.time DESC
          LIMIT 20
        `).bind(userId, todayStr).all();

        // 3. Current user details
        const userDetails = await env.DB.prepare(
          "SELECT username, email, package_name, total_credits, remaining_credits, package_expires, must_change_password, questionnaire, status FROM Clients WHERE id = ?"
        ).bind(userId).first();

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
        const { user_id, notification_ids } = await request.json();
        if (!user_id) {
          return jsonResponse({ success: false, error: "Korisnik ID je obavezan." }, 400);
        }

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
        const { user_id } = await request.json();
        if (!user_id) {
          return jsonResponse({ success: false, error: "Korisnik ID je obavezan." }, 400);
        }

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
            await logActivity(env, `Klijent '${clientName}' se prijavio (check-in) na termin '${booking.title}' u ${booking.time}h.`);
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
                await logActivity(env, `Klijent '${clientName}' se automatski prijavio na slobodni termin '${session.title}' u ${session.time}h.`);

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
        const { user_id, answers } = await request.json();
        if (!user_id || !answers) {
          return jsonResponse({ success: false, error: "Nedostaju parametri." }, 400);
        }

        const answersStr = JSON.stringify(answers);
        await env.DB.prepare("UPDATE Clients SET questionnaire = ? WHERE id = ?").bind(answersStr, user_id).run();
        
        // Log activity
        const user = await env.DB.prepare("SELECT username FROM Clients WHERE id = ?").bind(user_id).first();
        if (user) {
          await logActivity(env, `Klijent '${user.username}' je ispunio zdravstveni upitnik.`);
        }
        
        return jsonResponse({ success: true, message: "Upitnik uspješno spremljen." });
      }


      // --- ADMIN ONLY ENDPOINTS (Wife's dashboard) ---

      // ADMIN: GET PENDING CLIENTS
      if (request.method === "GET" && url.pathname === "/api/admin/pending-clients") {
        const { results } = await env.DB.prepare(
          "SELECT id, username, email, created_at, full_name FROM Clients WHERE status = 'pending' ORDER BY created_at DESC"
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
        await logActivity(env, `Admin je odobrio registraciju klijentu '${client.username}' i poslao mu privremenu lozinku.`);

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
        await logActivity(env, `Admin je odbio zahtjev za registraciju klijenta '${client.username}'.`);

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

        await logActivity(env, `Admin je potpuno obrisao klijenta '${client.username}' i sve njegove povezane podatke.`);

        return jsonResponse({ success: true, message: `Klijent '${client.username}' i svi njegovi podaci su obrisani.` });
      }

      // ADMIN: GET LIST OF APPROVED CLIENTS
      if (request.method === "GET" && url.pathname === "/api/admin/clients") {
        const { results } = await env.DB.prepare(`
          SELECT id, username, email, package_name, total_credits, remaining_credits, package_expires, created_at, questionnaire, status, full_name,
                 (SELECT COUNT(*) FROM Bookings b WHERE b.user_id = Clients.id AND b.status = 1) as attended_count
          FROM Clients
          WHERE is_admin = 0 AND status IN ('approved', 'frozen')
          ORDER BY COALESCE(full_name, username) ASC
        `).all();

        return jsonResponse({ success: true, clients: results });
      }

      // ADMIN: GET ACTIVITY LOGS
      if (request.method === "GET" && url.pathname === "/api/admin/activity-logs") {
        const { results } = await env.DB.prepare(
          "SELECT id, details, created_at FROM ActivityLogs ORDER BY id DESC LIMIT 30"
        ).all();
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

        // Insert client
        const result = await env.DB.prepare(`
          INSERT INTO Clients (username, email, password, is_admin, must_change_password, package_name, total_credits, remaining_credits, package_expires, full_name)
          VALUES (?, ?, ?, 0, 1, ?, ?, ?, ?, ?)
        `).bind(
          username, 
          email, 
          hashedTemp, 
          package_name || "Nema paketa", 
          parseInt(total_credits) || 0, 
          parseInt(total_credits) || 0, 
          expiresStr,
          full_name || null
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
          await logActivity(env, `Admin je ručno upisao dolazak klijentu '${details.username}' na termin '${details.title}' (${dateStr} u ${details.time}h).`);
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
            await logActivity(env, `Admin je otkazao termin klijentu '${details.username}' za '${details.title}' (${dateStr} u ${details.time}h) - uz povrat.`);
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
            await logActivity(env, `Admin je otkazao termin klijentu '${details.username}' za '${details.title}' (${dateStr} u ${details.time}h) - bez povrata.`);
          }

          // Notify waitlist when a session spot opens up
          await notifyWaitlist(env, booking.session_id);

          return jsonResponse({ success: true, message: "Rezervacija je otkazana bez povrata kredita (označeno kao nedolazak)." });
        }
      }

      // ADMIN: GET LIST OF SESSIONS & ATTENDEES FOR A DATE
      if (request.method === "GET" && url.pathname === "/api/admin/sessions-overview") {
        const dateStr = url.searchParams.get("date") || formatDate(getCroatiaNow());
        
        await autoConfirmBookings(env);
        
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
          SELECT b.id as booking_id, b.session_id, b.status, c.username, c.email, c.remaining_credits
          FROM Bookings b
          JOIN Clients c ON b.user_id = c.id
          JOIN Sessions s ON b.session_id = s.id
          WHERE s.date = ?
        `).bind(dateStr).all();

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

            // Rules:
            // Ponedjeljak (1) 07:00 i 10:00 su privatni
            if (dayOfWeek === 1 && (time === "07:00" || time === "10:00")) {
              type = "privatni";
              capacity = 1;
              title = "Privatni trening";
            }
            // Petak (5) 16:00 i 17:00 su privatni
            else if (dayOfWeek === 5 && (time === "16:00" || time === "17:00")) {
              type = "privatni";
              capacity = 1;
              title = "Privatni trening";
            }

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

        await logActivity(env, "Admin je ažurirao dugotrajni pristupni token za Instagram.");

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
        const { user_id, package_name } = await request.json();
        if (!user_id || !package_name) {
          return jsonResponse({ success: false, error: "Nedostaju parametri." }, 400);
        }

        const client = await env.DB.prepare("SELECT username, email, remaining_credits FROM Clients WHERE id = ?").bind(user_id).first();
        if (!client) {
          return jsonResponse({ success: false, error: "Korisnik nije pronađen." }, 404);
        }

        if (client.remaining_credits > 0) {
          return jsonResponse({ success: false, error: "Nije moguće zatražiti novi paket dok ne iskoristite sve treninge iz postojećeg." }, 400);
        }

        const activeRequest = await env.DB.prepare("SELECT id FROM PackageRequests WHERE user_id = ? AND status = 'pending'").bind(user_id).first();
        if (activeRequest) {
          return jsonResponse({ success: false, error: "Već imate aktivan zahtjev za paket na čekanju." }, 400);
        }

        // Save request to DB
        await env.DB.prepare("INSERT INTO PackageRequests (user_id, package_name, status) VALUES (?, ?, 'pending')").bind(user_id, package_name).run();

        // Log activity
        await logActivity(env, `Klijent '${client.username}' je zatražio novi paket: '${package_name}'.`);

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

        await logActivity(env, `Admin je odobrio zahtjev za paket '${package_name}' klijentu '${client.username}'.`);

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
          await logActivity(env, `Admin je odbio zahtjev za paket '${package_name}' klijentu '${client.username}'.`);
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
    ctx.waitUntil(syncInstagramFeed(env));
  }
};