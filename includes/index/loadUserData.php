<?php
/**
 * loadUserData.php — Loads all user/club/permission data for index.php
 *
 * FIX #3: Replaced all raw $pdo->prepare()/execute()/fetch() calls with
 * db.php helper functions (dbQueryOne, dbQuery). This ensures:
 *   - Consistent error handling through the helpers' try/catch + error_log
 *   - No dependency on the raw $pdo global surviving across includes
 *   - If the connection was lost between db.php init and this file (e.g.
 *     MySQL timeout), helpers call getDBConnection() which reconnects.
 *
 * FIX #3: Replaced die("An error occurred...") with a clean redirect.
 * Previously, if a PDOException occurred, die() would output plain text
 * mid-HTML-document (since index.php's <!DOCTYPE> could have already been
 * buffered), producing a malformed page. Now we redirect to login.php
 * with an error flag so the user gets a clean page.
 *
 * All redirects call ob_end_clean() to discard any buffered output from
 * index.php's ob_start() before sending Location headers.
 */
try {
    $user = dbQueryOne(
        "SELECT id, first_name, last_name, email, is_system_owner FROM users WHERE id = ?",
        [$_SESSION['user_id']]
    );

    if (!$user) {
        session_destroy();
        ob_end_clean();
        header('Location: login.php');
        exit;
    }

    // Redirect system owners to their dashboard
    if ($user['is_system_owner']) {
        ob_end_clean();
        header('Location: super-owner-dashboard.php');
        exit;
    }

    // Load user's clubs with permissions
    $clubs = dbQuery(
        "SELECT 
            c.id,
            c.name,
            c.access_code,
            c.description,
            cm.is_president,
            cr.role_name,
            cr.id as role_id
        FROM club_members cm
        JOIN clubs c ON c.id = cm.club_id
        JOIN club_roles cr ON cr.id = cm.role_id
        WHERE cm.user_id = ? AND cm.status = 'active' AND c.is_active = TRUE
        ORDER BY c.name",
        [$user['id']]
    );

    if (empty($clubs)) {
        ob_end_clean();
        header('Location: no-clubs.php');
        exit;
    }

    // Set active club
    if (!isset($_SESSION['active_club_id']) || !in_array($_SESSION['active_club_id'], array_column($clubs, 'id'))) {
        $_SESSION['active_club_id'] = $clubs[0]['id'];
    }

    // Get active club details
    $activeClub = null;
    foreach ($clubs as $club) {
        if ($club['id'] == $_SESSION['active_club_id']) {
            $activeClub = $club;
            break;
        }
    }

    // Safety fallback: if active_club_id didn't match any club (shouldn't happen,
    // but prevents null reference errors in downstream code)
    if (!$activeClub) {
        $activeClub = $clubs[0];
        $_SESSION['active_club_id'] = $activeClub['id'];
    }

    // Load permissions for active club
    $permissionsArray = dbQuery(
        "SELECT permission_key, permission_value FROM role_permissions WHERE role_id = ?",
        [$activeClub['role_id']]
    );

    // Convert to associative array
    $permissions = [];
    foreach ($permissionsArray as $perm) {
        $permissions[$perm['permission_key']] = (bool)$perm['permission_value'];
    }

    // Load user notifications
    $notifications = dbQuery(
        "SELECT * FROM notifications WHERE user_id = ? AND is_read = FALSE ORDER BY created_at DESC LIMIT 10",
        [$user['id']]
    );
    $unreadCount = count($notifications);

} catch (PDOException $e) {
    error_log("loadUserData.php - Database error: " . $e->getMessage());
    ob_end_clean();
    header('Location: login.php?error=db');
    exit;
} catch (Exception $e) {
    error_log("loadUserData.php - Unexpected error: " . $e->getMessage());
    ob_end_clean();
    header('Location: login.php?error=unknown');
    exit;
}
?>