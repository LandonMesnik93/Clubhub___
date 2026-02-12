<?php
/**
 * logout.php - Session Logout Handler (Canonical Endpoint)
 * Club Hub Management System
 *
 * FIXES APPLIED:
 * - Removed mangled double-if with mismatched braces on line 14
 * - Fixed CSRF header key: HTTP_CSRF_TOKEN → HTTP_X_CSRF_TOKEN
 *   (JS sends X-CSRF-Token, PHP maps that to HTTP_X_CSRF_TOKEN)
 * - Replaced unsafe !== comparison with hash_equals() via requireCSRFForMutation()
 * - Now uses db.php helpers (jsonResponse) instead of manual json_encode output
 * - Removed redundant session_start() (db.php handles it)
 * - Removed unused json_decode of request body
 * - FIX #2: Graceful CSRF handling for expired/invalidated sessions.
 *   If the session has already expired (e.g. via session_regenerate_id or timeout),
 *   $_SESSION['csrf_token'] is null, causing verifyCSRFToken() to always fail
 *   and locking the user out of logging out. Now: if there is no active login,
 *   the user is already effectively logged out — skip CSRF and confirm success.
 *   CSRF is still enforced when an active session exists (prevents CSRF logout attacks).
 */

require_once __DIR__ . '/database/db.php';

// Only allow POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonResponse(false, null, 'Invalid request method');
}

// Determine session state BEFORE CSRF check
$hasActiveLogin = isLoggedIn();
$token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
$hasValidCSRF = isset($_SESSION['csrf_token']) && $token && hash_equals($_SESSION['csrf_token'], $token);

// If user has an active session but CSRF is invalid, reject (prevents CSRF logout attacks).
// If user has NO active session, CSRF cannot be validated because the session is gone —
// the user is already logged out, so just confirm and clean up.
if ($hasActiveLogin && !$hasValidCSRF) {
    jsonResponse(false, null, 'Invalid or missing CSRF token');
}

// Clean up the DB session record if user was logged in
if ($hasActiveLogin) {
    try {
        $userId = getCurrentUserId();
        dbExecute("DELETE FROM sessions WHERE id = ?", [session_id()]);
        logActivity($userId, 'logout');
    } catch (Exception $e) {
        error_log('Logout cleanup error: ' . $e->getMessage());
        // Continue with session destruction even if DB cleanup fails
    }
}

// Destroy session safely
session_unset();
session_destroy();

// Clear session cookie
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// Start a fresh session so jsonResponse/generateCSRFToken can access $_SESSION
session_start();

jsonResponse(true, null, 'Logged out successfully');