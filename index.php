<?php

// Modern URL Shortener with Konami Code Admin Panel

// Enable error reporting for debugging.
// IMPORTANT: Turn this OFF in a production environment for security.
ini_set('display_errors', 1);
error_reporting(E_ALL);
clearstatcache();
// Define file paths for data storage
$protDir       = __DIR__ . '/prot';
$storageFile   = __DIR__ . '/urls.json';
$blacklistFile = __DIR__ . '/blacklist.json';
$shadowFile    = $protDir . '/shadow.json';
//create htaccess for safety
$content_home_htaccess = "# Turn on the Rewrite Engine\nRewriteEngine On\n\n# Base directory for rewriting (adjust if your script is in a subdirectory)\n# If your script is at example.com/shortener/index.php, use /shortener/\n# If your script is at example.com/index.php, use /\nRewriteBase /\n\n# Rule to handle requests for short URLs\n# If the request is not for an existing file (-f) or directory (-d)\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\n# And the request looks like a short code (alphanumeric, underscore, hyphen)\n# Then rewrite it to index.php?code=<the_short_code>\n# [L] means Last rule (stop processing rules)\n# [QSA] means Query String Append (append any existing query string)\nRewriteRule ^([a-zA-Z0-9_-]+)/?$ index.php?code=\$1 [L,QSA]\n<FilesMatch \"^(url|blacklist)\\.json$\">\n    Order allow,deny\n    Deny from all\n</FilesMatch>\n\nErrorDocument 404 /404.html\nErrorDocument 403 /403.html\n";

$htaccessFile = __DIR__ . '/.htaccess';

if (!file_exists($htaccessFile)) {
    if (file_put_contents($htaccessFile, $content_home_htaccess) === false) {
        http_response_code(500);
        die("Error: Could not create .htaccess file. Check permissions.");
    }
}



//creating 404
$content_404_html = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width, initial-scale=1.0"/><title>404 Not Found</title><style>body{margin:0;padding:0;background:linear-gradient(135deg,#2c3e50,#000000);height:100vh;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,Oxygen,Ubuntu,Cantarell,\'Open Sans\',\'Helvetica Neue\',sans-serif;display:flex;align-items:center;justify-content:center;overflow:hidden}.glass-card{backdrop-filter:blur(15px);-webkit-backdrop-filter:blur(15px);background:rgba(255,255,255,0.07);border-radius:16px;padding:60px 40px;text-align:center;border:1px solid rgba(255,255,255,0.2);box-shadow:0 8px 32px rgba(0,0,0,0.25)}.code{font-size:7rem;font-weight:800;color:white;letter-spacing:2px;text-shadow:0 0 6px rgba(255,255,255,0.2)}.message{font-size:1.4rem;color:#e0e0e0;margin-top:10px}@media (max-width:600px){.glass-card{padding:40px 20px}.code{font-size:5rem}.message{font-size:1.1rem}}</style></head><body><div class="glass-card"><div class="code">404</div><div class="message">The requested resource or short URL could not be found.</div></div></body></html>';

$file_404_html = __DIR__ . '/404.html';

if (!file_exists($file_404_html)) {
    if (file_put_contents($file_404_html, $content_404_html) === false) {
        http_response_code(500);
        die("Error: Could not create 404.html file. Check permissions.");
    }
}
//creating 403
$content_403_html = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width, initial-scale=1.0"/><title>403 Forbidden</title><style>body{margin:0;padding:0;background:linear-gradient(135deg,#2c3e50,#000000);height:100vh;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,Oxygen,Ubuntu,Cantarell,\'Open Sans\',\'Helvetica Neue\',sans-serif;display:flex;align-items:center;justify-content:center;overflow:hidden}.glass-card{backdrop-filter:blur(15px);-webkit-backdrop-filter:blur(15px);background:rgba(255,255,255,0.07);border-radius:16px;padding:60px 40px;text-align:center;border:1px solid rgba(255,255,255,0.2);box-shadow:0 8px 32px rgba(0,0,0,0.25)}.code{font-size:7rem;font-weight:800;color:white;letter-spacing:2px;text-shadow:0 0 6px rgba(255,255,255,0.2)}.message{font-size:1.4rem;color:#e0e0e0;margin-top:10px}@media (max-width:600px){.glass-card{padding:40px 20px}.code{font-size:5rem}.message{font-size:1.1rem}}</style></head><body><div class="glass-card"><div class="code">403</div><div class="message">You don\'t have permission to access this resource.</div></div></body></html>';

$file_403_html = __DIR__ . '/403.html';

if (!file_exists($file_403_html)) {
    if (file_put_contents($file_403_html, $content_403_html) === false) {
        http_response_code(500);
        die("Error: Could not create 403.html file. Check permissions.");
    }
}
// --- Initialization: Ensure directories and files exist ---

// Ensure 'prot' directory exists and set appropriate permissions
if (!is_dir($protDir)) {
    // 0755 means owner has read/write/execute, group and others have read/execute
    // 'true' allows recursive creation of parent directories
    if (!mkdir($protDir, 0755, true)) {
        http_response_code(500);
        die("Error: Could not create protected directory '$protDir'. Check permissions.");
    }

    // IMPORTANT: Add a .htaccess file to deny direct web access to /prot/ directory if using Apache
    // This prevents sensitive files (like shadow.json) from being accessed directly via URL.
    if (!file_exists($protDir . '/.htaccess')) {
        if (file_put_contents($protDir . '/.htaccess', 'Deny from all') === false) {
            http_response_code(500);
            die("Error: Could not create .htaccess in '$protDir'. Check permissions.");
        }
    }
}

// Ensure data files exist; create empty JSON arrays if they don't.
// It's crucial that the web server user has write permissions to these files.
if (!file_exists($storageFile)) {
    if (file_put_contents($storageFile, json_encode([])) === false) {
        http_response_code(500);
        die("Error: Could not create storage file '$storageFile'. Check permissions.");
    }
}

if (!file_exists($blacklistFile)) {
    if (file_put_contents($blacklistFile, json_encode([])) === false) {
        http_response_code(500);
        die("Error: Could not create blacklist file '$blacklistFile'. Check permissions.");
    }
}

if (!file_exists($shadowFile)) {
    // Create default admin: username 'admin', password 'admin123'
    // IMPORTANT: Change default credentials immediately after setup!
    $defaultAdmin = ['admin' => password_hash('admin123', PASSWORD_DEFAULT)];
    if (file_put_contents($shadowFile, json_encode($defaultAdmin, JSON_PRETTY_PRINT)) === false) {
        http_response_code(500);
        die("Error: Could not create shadow file '$shadowFile'. Check permissions.");
    }
}

// --- Load data from JSON files (with basic error handling) ---

/**
 * Function to safely read JSON, returning an empty array on failure or malformed JSON.
 * Logs errors for debugging.
 * @param string $file The path to the JSON file.
 * @return array The decoded data, or an empty array on failure.
 */
function safeReadJson($file) {
    if (!file_exists($file)) {
        return []; // File doesn't exist yet, return empty
    }
    $contents = file_get_contents($file);
    if ($contents === false) {
        error_log("Failed to read file: $file");
        return [];
    }
    $data = json_decode($contents, true);
    if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
        error_log("Error decoding JSON from $file: " . json_last_error_msg());
        return []; // Malformed JSON, return empty array to prevent further errors
    }
    return is_array($data) ? $data : []; // Ensure it's an array
}

$urls      = safeReadJson($storageFile);
$blacklist = safeReadJson($blacklistFile);
$admins    = safeReadJson($shadowFile); // This variable is updated by admin actions

// Start PHP session for admin login management
session_start();

// --- Utility Functions ---

/**
 * Safely writes data to a JSON file with exclusive lock to prevent race conditions.
 * @param string $file The path to the JSON file.
 * @param array $data The data array to encode and write.
 * @return bool True on success, false on failure.
 */
function safeWriteJson($file, $data) {
    // Use 'c+' mode: create if not exists, open for read/write, place pointer at start.
    // 'w' would truncate immediately, which is bad if flock fails.
    $fp = fopen($file, 'c+');
    if ($fp === false) {
        error_log("Failed to open file for writing: $file");
        return false;
    }

    // Attempt to acquire an exclusive lock
    if (flock($fp, LOCK_EX)) {
        // Truncate the file to zero length
        ftruncate($fp, 0);
        // Rewind the file pointer to the beginning
        rewind($fp);
        // Write the JSON data
        $result = fwrite($fp, json_encode($data, JSON_PRETTY_PRINT));
        // Flush output buffer to ensure data is written to disk
        fflush($fp);
        // Release the lock
        flock($fp, LOCK_UN);
        fclose($fp);
        return $result !== false;
    } else {
        error_log("Could not acquire file lock for: $file");
        fclose($fp);
        return false;
    }
}

/**
 * Generates a random alphanumeric code of a specified length.
 * @param int $length The desired length of the code.
 * @return string The generated code.
 */
function generateCode($length = 6) {
    $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $code = '';
    for ($i = 0; $i < $length; $i++) {
        // Use random_int for cryptographically secure pseudo-random number generation
        $code .= $chars[random_int(0, strlen($chars) - 1)];
    }
    return $code;
}

/**
 * Displays a 403 Forbidden page for blacklisted IPs.
 */
function showBlacklistedPage() {
    http_response_code(403); // Set HTTP status code to 403 Forbidden
    readfile('403.html');
    exit; // Terminate script execution
}

/**
 * Validates password strength (min 8 chars, at least one uppercase, one lowercase, one number, one special character).
 * @param string $password The password to validate.
 * @return bool True if password meets criteria, false otherwise.
 */
function validatePasswordStrength($password) {
    if (strlen($password) < 8) {
        return false;
    }
    if (!preg_match('/[A-Z]/', $password)) { // At least one uppercase
        return false;
    }
    if (!preg_match('/[a-z]/', $password)) { // At least one lowercase
        return false;
    }
    if (!preg_match('/[0-9]/', $password)) { // At least one digit
        return false;
    }
    if (!preg_match('/[^A-Za-z0-9]/', $password)) { // At least one special character
        return false;
    }
    return true;
}

// --- Main Application Logic ---

// ========== URL REDIRECTION ===========
if (isset($_GET['code']) && $_SERVER['REQUEST_METHOD'] === 'GET') {
    $code = $_GET['code'];
    // Check if the client's IP is blacklisted before redirecting
    if (in_array($_SERVER['REMOTE_ADDR'], $blacklist)) {
        showBlacklistedPage();
    }
    // Perform redirection if code exists
    if (isset($urls[$code])) {
        // Use 301 Permanent Redirect for SEO benefits
        header("Location: " . $urls[$code], true, 301);
        exit;
    } else {
        // Display 404 Not Found if the short URL doesn't exist
        http_response_code(404);
        //echo "404 Not Found - The short URL does not exist.";
        readfile("404.html");
        exit;
    }
}

// ========== SHORTEN URL FORM SUBMISSION ===========
$error = '';    // Variable to store error messages for the UI
$success = '';  // Variable to store success messages for the UI
$shortUrl = ''; // Variable to store the generated short URL for the UI

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['url']) && !isset($_POST['admin_action'])) {
    $longUrl = trim($_POST['url']);
    $custom = trim($_POST['custom'] ?? ''); // Null coalescing operator for PHP 7.0+

    // Validate URL format
    if (!filter_var($longUrl, FILTER_VALIDATE_URL)) {
        $error = "Invalid URL format. Please include http:// or https://";
    } elseif (in_array($_SERVER['REMOTE_ADDR'], $blacklist)) {
        // Prevent submission if IP is blacklisted
        showBlacklistedPage();
    } else {
        // Handle custom short code
        if ($custom !== '') {
            // Short code can be alphanumeric, underscore, or hyphen. 3-20 characters long.
            if (!preg_match('/^[a-zA-Z0-9_-]{3,20}$/', $custom)) {
                $error = "Custom code must be 3-20 characters: letters, numbers, underscore, or hyphen.";
            } elseif (isset($urls[$custom])) {
                $error = "That custom short code is already in use.";
            } else {
                $code = $custom; // Custom code is valid and available
            }
        } else {
            // Generate a random code if no custom code is provided
            $existing = array_search($longUrl, $urls, true);
            if ($existing !== false) {
                // If the long URL already exists, use its existing short code
                $code = $existing;
            } else {
                // Generate a new unique short code
                do {
                    $code = generateCode(6);
                } while (isset($urls[$code]));
            }
        }
    }

    // If no errors, save the URL
    if (empty($error) && isset($code)) {
        $urls[$code] = $longUrl;
        if (safeWriteJson($storageFile, $urls)) { // Check if write was successful
            // Construct the full short URL
            $scheme = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http';
            $shortUrl = sprintf('%s://%s%s/%s', $scheme, $_SERVER['HTTP_HOST'], dirname($_SERVER['PHP_SELF']) == '/' ? '' : dirname($_SERVER['PHP_SELF']), htmlspecialchars($code));
            $success = "Short URL created successfully!";
        } else {
            $error = "Failed to save URL. Check server permissions or logs.";
        }
    }
}

// ========== ADMIN LOGIN & ACTIONS ===========

/**
 * Checks if the current session is authenticated as an admin.
 * @return bool True if logged in as admin, false otherwise.
 */
function isAdmin() {
    return isset($_SESSION['admin']) && $_SESSION['admin'] === true;
}

// Handle AJAX requests for admin panel actions
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['admin_action'])) {
    header('Content-Type: application/json'); // Respond with JSON

    $response = ['success' => false, 'message' => 'Unknown error', 'data' => []];

    // Require authentication for all admin actions except 'login'
    if ($_POST['admin_action'] !== 'login' && !isAdmin()) {
        $response['message'] = "Unauthorized. Please log in.";
        http_response_code(403); // Forbidden
        echo json_encode($response);
        exit;
    }

    // Reload admins data from file for consistency, especially after changes
    // This is important because $admins might have been loaded before a write in another request.
    $admins = safeReadJson($shadowFile);

    switch ($_POST['admin_action']) {
        case 'login':
            $user = $_POST['username'] ?? '';
            $pass = $_POST['password'] ?? '';
            if (isset($admins[$user]) && password_verify($pass, $admins[$user])) {
                $_SESSION['admin'] = true;
                $_SESSION['username'] = $user; // Store username in session
                $response = ['success' => true, 'message' => 'Login successful', 'data' => ['username' => $user]];
            } else {
                $response = ['success' => false, 'message' => 'Invalid username or password'];
            }
            break;

        case 'logout':
            session_destroy(); // End the session
            // Clear session variables to be safe
            $_SESSION = [];
            $response = ['success' => true, 'message' => 'Logged out successfully'];
            break;

        case 'get_lists': // Action to fetch all lists for dynamic updates in admin panel
            // Re-read data from files to ensure the latest state is sent to the client
            $urls = safeReadJson($storageFile);
            $blacklist = safeReadJson($blacklistFile);
            $admins = safeReadJson($shadowFile);

            $response = [
                'success' => true,
                'data' => [
                    'urls'      => $urls,
                    'blacklist' => $blacklist,
                    'admins'    => array_keys($admins), // Only send usernames, not password hashes
                    'current_user' => $_SESSION['username'] ?? null // Send current logged-in user
                ]
            ];
            break;

        case 'clear_urls':
            $urls = []; // Clear the URLs array
            if (safeWriteJson($storageFile, $urls)) {
                $response = ['success' => true, 'message' => 'All URLs cleared successfully!', 'data' => ['urls' => $urls]];
            } else {
                $response = ['success' => false, 'message' => 'Failed to clear URLs.'];
            }
            break;

        case 'delete_url':
            $codeToDelete = $_POST['code'] ?? '';
            if (isset($urls[$codeToDelete])) {
                unset($urls[$codeToDelete]);
                if (safeWriteJson($storageFile, $urls)) {
                    $response = ['success' => true, 'message' => "URL '$codeToDelete' deleted.", 'data' => ['urls' => $urls]];
                } else {
                    $response = ['success' => false, 'message' => "Failed to delete URL '$codeToDelete'. Check permissions or server logs."];
                }
            } else {
                $response = ['success' => false, 'message' => 'URL code not found.'];
            }
            break;

        case 'add_blacklist':
            $ip = $_POST['ip'] ?? '';
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                if (!in_array($ip, $blacklist)) {
                    $blacklist[] = $ip; // Add IP to blacklist
                    if (safeWriteJson($blacklistFile, $blacklist)) {
                        $response = ['success' => true, 'message' => "IP $ip blacklisted.", 'data' => ['blacklist' => $blacklist]];
                    } else {
                        $response = ['success' => false, 'message' => "Failed to add IP to blacklist. Check permissions or server logs."];
                    }
                } else {
                    $response = ['success' => false, 'message' => "IP $ip is already blacklisted."];
                }
            } else {
                $response = ['success' => false, 'message' => 'Invalid IP address format.'];
            }
            break;

        case 'remove_blacklist':
            $ip = $_POST['ip'] ?? '';
            if (($key = array_search($ip, $blacklist)) !== false) {
                unset($blacklist[$key]); // Remove IP
                $blacklist = array_values($blacklist); // Re-index array after removal
                if (safeWriteJson($blacklistFile, $blacklist)) {
                    $response = ['success' => true, 'message' => "IP $ip removed from blacklist.", 'data' => ['blacklist' => $blacklist]];
                } else {
                    $response = ['success' => false, 'message' => "Failed to remove IP from blacklist. Check permissions or server logs."];
                }
            } else {
                $response = ['success' => false, 'message' => 'IP not found in blacklist.'];
            }
            break;

        case 'add_admin':
            $newUser = $_POST['new_username'] ?? '';
            $newPass = $_POST['new_password'] ?? '';
            $confirmPass = $_POST['confirm_password'] ?? '';

            if (empty($newUser)) {
                $response = ['success' => false, 'message' => 'Username cannot be empty.'];
                break;
            }
            if (!validatePasswordStrength($newPass)) {
                $response = ['success' => false, 'message' => 'Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters.'];
                break;
            }
            if ($newPass !== $confirmPass) {
                $response = ['success' => false, 'message' => 'Passwords do not match.'];
                break;
            }
            if (isset($admins[$newUser])) {
                $response = ['success' => false, 'message' => 'Username already exists.'];
                break;
            }
            $admins[$newUser] = password_hash($newPass, PASSWORD_DEFAULT); // Hash password
            if (safeWriteJson($shadowFile, $admins)) {
                $response = ['success' => true, 'message' => 'Admin user added successfully.', 'data' => ['admins' => array_keys($admins)]];
            } else {
                $response = ['success' => false, 'message' => "Failed to add admin user. Check permissions or server logs."];
            }
            break;

        case 'remove_admin':
            $delUser = $_POST['del_username'] ?? '';

            if ($delUser === ($_SESSION['username'] ?? '')) {
                $response = ['success' => false, 'message' => 'You cannot remove your own admin account.'];
                break;
            }
            if (count($admins) <= 1) { // If only one admin exists
                $response = ['success' => false, 'message' => 'Cannot remove the only admin user.'];
                break;
            }

            if (isset($admins[$delUser])) {
                unset($admins[$delUser]);
                if (safeWriteJson($shadowFile, $admins)) {
                    $response = ['success' => true, 'message' => 'Admin user removed.', 'data' => ['admins' => array_keys($admins)]];
                } else {
                    $response = ['success' => false, 'message' => "Failed to remove admin user. Check permissions or server logs."];
                }
            } else {
                $response = ['success' => false, 'message' => 'Admin user not found.'];
            }
            break;

        case 'change_username':
            $currentUsername = $_SESSION['username'] ?? '';
            $newUsername = $_POST['new_username'] ?? '';
            $currentPassword = $_POST['current_password'] ?? ''; // Renamed for clarity

            if (empty($currentUsername) || !isset($admins[$currentUsername])) {
                $response = ['success' => false, 'message' => 'Not logged in as an admin or session expired. Please re-login.'];
                break;
            }
            if (!password_verify($currentPassword, $admins[$currentUsername])) {
                $response = ['success' => false, 'message' => 'Incorrect current password.'];
                break;
            }
            if (empty($newUsername)) {
                $response = ['success' => false, 'message' => 'New username cannot be empty.'];
                break;
            }
            if (isset($admins[$newUsername]) && $newUsername !== $currentUsername) {
                $response = ['success' => false, 'message' => 'New username already exists. Please choose a different one.'];
                break;
            }

            // Perform the change
            $hashedPassword = $admins[$currentUsername]; // Keep the old hash
            unset($admins[$currentUsername]);
            $admins[$newUsername] = $hashedPassword;

            if (safeWriteJson($shadowFile, $admins)) {
                $_SESSION['username'] = $newUsername; // Update session
                $response = ['success' => true, 'message' => 'Username changed successfully!', 'data' => ['current_user' => $newUsername, 'admins' => array_keys($admins)]];
            } else {
                $response = ['success' => false, 'message' => 'Failed to change username. Check permissions or server logs.'];
            }
            break;

        case 'change_password':
            $currentUsername = $_SESSION['username'] ?? '';
            $currentPassword = $_POST['current_password'] ?? '';
            $newPassword = $_POST['new_password'] ?? '';
            // Removed 'confirm_new_password' as requested

            if (empty($currentUsername) || !isset($admins[$currentUsername])) {
                $response = ['success' => false, 'message' => 'Not logged in as an admin or session expired. Please re-login.'];
                break;
            }
            if (!password_verify($currentPassword, $admins[$currentUsername])) {
                $response = ['success' => false, 'message' => 'Incorrect current password.'];
                break;
            }
            if (!validatePasswordStrength($newPassword)) {
                $response = ['success' => false, 'message' => 'New password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters.'];
                break;
            }
            if (password_verify($newPassword, $admins[$currentUsername])) { // Check if new password is same as old
                $response = ['success' => false, 'message' => 'New password cannot be the same as the current password.'];
                break;
            }

            // Update the password
            $admins[$currentUsername] = password_hash($newPassword, PASSWORD_DEFAULT);
            if (safeWriteJson($shadowFile, $admins)) {
                $response = ['success' => true, 'message' => 'Password changed successfully!'];
            } else {
                $response = ['success' => false, 'message' => 'Failed to change password. Check permissions or server logs.'];
            }
            break;

        default:
            $response = ['success' => false, 'message' => 'Invalid admin action.'];
    }

    echo json_encode($response);
    exit; // Terminate script after AJAX response
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Minimalist URL Shortener</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #121212; /* Even darker background */
            --surface-color: #1e1e1e; /* Slightly lighter surface for cards/modals */
            --primary-color: #007bff; /* A vibrant blue */
            --primary-hover-color: #0056b3;
            --text-color: #e0e0e0;
            --text-muted-color: #888;
            --error-color: #ff4d4f;
            --success-color: #52c41a;
            --border-radius: 8px;
            --font-family: 'Inter', sans-serif;
        }
        * {
            box-sizing: border-box; /* IMPORTANT: Ensures padding and border are included in the element's total width and height */
            margin: 0;
            padding: 0;
        }
        body {
            font-family: var(--font-family);
            background: var(--bg-color);
            color: var(--text-color);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 1.5rem;
            font-size: 16px; /* Base font size */
        }
        .container {
            background: var(--surface-color);
            border-radius: var(--border-radius);
            padding: 2rem; /* Increased padding */
            width: 100%;
            max-width: 450px; /* Slightly wider */
            box-shadow: 0 8px 24px rgba(0,0,0,0.3);
            text-align: center;
        }
        h1 {
            color: var(--primary-color);
            margin-bottom: 1.5rem;
            font-weight: 700;
            font-size: 2em;
        }
        form {
            display: flex;
            flex-direction: column;
            gap: 1rem; /* Spacing between form elements */
        }
        input[type="url"], input[type="text"], input[type="password"] {
            background: #2a2a2a; /* Darker inputs */
            border: 1px solid #383838; /* Subtle border */
            border-radius: var(--border-radius);
            padding: 0.9rem 1rem; /* More padding */
            color: var(--text-color);
            font-size: 1rem;
            transition: border-color 0.2s, box-shadow 0.2s;
            width: 100%; /* Ensure inputs take full width of their container */
        }
        input[type="url"]:focus, input[type="text"]:focus, input[type="password"]:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(0, 123, 255, 0.25);
        }
        button {
            background: var(--primary-color);
            border: none;
            border-radius: var(--border-radius);
            padding: 0.9rem 1rem;
            font-weight: 500; /* Medium weight */
            color: #fff;
            cursor: pointer;
            transition: background-color 0.2s;
            font-size: 1rem;
            width: 100%; /* Ensure buttons take full width of their container */
        }
        button:hover {
            background: var(--primary-hover-color);
        }
        .message {
            padding: 0.8rem 1rem;
            border-radius: var(--border-radius);
            margin-bottom: 1rem;
            font-weight: 500;
            text-align: left;
            line-height: 1.5;
        }
        .error {
            background-color: rgba(255, 77, 79, 0.1); /* Softer error bg */
            color: var(--error-color);
            border: 1px solid var(--error-color);
        }
        .success {
            background-color: rgba(82, 196, 26, 0.1); /* Softer success bg */
            color: var(--success-color);
            border: 1px solid var(--success-color);
        }
        .short-url-display {
            background: #2a2a2a;
            color: var(--primary-color);
            padding: 0.8rem 1rem;
            border-radius: var(--border-radius);
            text-align: center;
            font-weight: 500;
            user-select: all;
            cursor: pointer;
            margin: 1rem 0;
            word-break: break-all;
            border: 1px solid var(--primary-color);
            transition: background-color 0.2s;
        }
        .short-url-display:hover {
            background-color: #333;
        }

        /* Admin Modal & Panel Styles */
        .modal-overlay, #admin-panel {
            display: none; /* Hidden by default */
            position: fixed;
            inset: 0;
            z-index: 1000;
            background: rgba(0,0,0,0.7); /* Darker overlay */
            backdrop-filter: blur(5px);
        }
        .modal-overlay.active, #admin-panel.active {
            display: flex; /* Use flex for centering modal content */
            justify-content: center;
            align-items: center;
        }
        #admin-panel.active { /* For panel, allow scrolling */
            align-items: flex-start;
            justify-content: flex-start;
            overflow-y: auto;
            padding: 2rem;
            flex-direction: column; /* Ensure content stacks vertically */
        }

        .modal-content {
            background: var(--surface-color);
            padding: 2rem;
            border-radius: var(--border-radius);
            width: 100%;
            max-width: 400px;
            box-shadow: 0 8px 30px rgba(0,0,0,0.3);
            animation: fadeInScaleModal 0.3s ease-out;
        }
        #admin-panel-content { /* Specific for admin panel inner structure */
            background: var(--surface-color);
            padding: 1.5rem; /* Slightly less padding for inner sections */
            border-radius: var(--border-radius);
            width: 100%;
            max-width: 800px; /* Wider for admin content */
            margin: auto; /* Center if panel itself is flexed */
            animation: fadeInScaleModal 0.3s ease-out;
            display: flex;
            flex-direction: column;
            gap: 1.5rem; /* Gap between sections */
        }

        @keyframes fadeInScaleModal {
            from { opacity: 0; transform: scale(0.95); }
            to { opacity: 1; transform: scale(1); }
        }
        .modal-content h2, #admin-panel-content header h2 {
            color: var(--primary-color);
            margin-bottom: 1.5rem;
            text-align: center;
        }
        #admin-panel-content header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem; /* Adjusted for gap on #admin-panel-content */
            padding-bottom: 1rem;
            border-bottom: 1px solid #383838; /* Subtle separator */
        }
        #admin-panel-content header button#logout-btn {
            background-color: var(--error-color);
        }
        #admin-panel-content header button#logout-btn:hover {
            background-color: #c82333; /* Darker red */
        }

        #admin-panel-content section {
            /* margin-bottom: 2rem; Removed due to gap on parent */
            background: #252525; /* Slightly different bg for sections */
            border-radius: var(--border-radius);
            padding: 1.5rem;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
            display: flex;
            flex-direction: column;
            gap: 1rem; /* Gap within sections */
        }
        #admin-panel-content section h3 {
            color: var(--primary-color);
            margin-bottom: 0.5rem; /* Adjusted for gap on parent */
            border-bottom: 1px solid #383838;
            padding-bottom: 0.5rem;
        }
        #admin-panel-content section h4 {
            color: var(--text-color);
            margin-top: 0.5rem;
            margin-bottom: 0.5rem;
        }

        .admin-input-group {
            display: flex;
            flex-wrap: wrap; /* Allow items to wrap on smaller screens */
            gap: 0.75rem;
            align-items: center;
        }
        .admin-input-group input {
            flex: 1 1 auto; /* Allow input to grow/shrink and wrap */
            min-width: 120px; /* Minimum width before wrapping */
            margin-bottom: 0; /* Override global input margin */
        }
        .admin-input-group button {
            flex-shrink: 0; /* Prevent button from shrinking */
            width: auto; /* Allow button to size naturally */
            padding: 0.9rem 1.2rem; /* Ensure consistent button padding */
        }

        #admin-panel-content ul {
            list-style: none;
            padding: 0;
            max-height: 250px; /* Limit height for scrollable lists */
            overflow-y: auto;
            border: 1px solid #383838;
            border-radius: var(--border-radius);
        }
        #admin-panel-content ul li {
            padding: 0.75rem 1rem;
            border-bottom: 1px solid #303030; /* Darker list item separator */
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.9em;
            word-break: break-all;
        }
        #admin-panel-content ul li:last-child {
            border-bottom: none;
        }
        #admin-panel-content ul li a {
            color: var(--primary-color);
            text-decoration: none;
            margin-left: 0.5rem;
            font-weight: 400;
        }
        #admin-panel-content ul li a:hover {
            text-decoration: underline;
        }
        #admin-panel-content ul li strong { color: var(--text-color); }

        #admin-panel-content ul li button.remove-btn {
            background: var(--error-color);
            color: white;
            border: none;
            padding: 0.4rem 0.8rem;
            border-radius: var(--border-radius);
            cursor: pointer;
            font-size: 0.85rem;
            transition: background-color 0.2s;
            margin-left: 10px; /* Space out from text */
            width: auto; /* Override global button width */
        }
        #admin-panel-content ul li button.remove-btn:hover {
            background: #c82333; /* Darker red */
        }
        
        .admin-message {
            padding: 0.6rem 1rem;
            border-radius: var(--border-radius);
            margin-top: 0; /* Reset margin top */
            margin-bottom: 0; /* Reset margin bottom */
            font-weight: 500;
            text-align: left;
            line-height: 1.4;
            display: none; /* Hidden by default */
        }
        .admin-message.error {
            background-color: rgba(255, 77, 79, 0.1);
            color: var(--error-color);
            border: 1px solid var(--error-color);
        }
        .admin-message.success {
            background-color: rgba(82, 196, 26, 0.1);
            color: var(--success-color);
            border: 1px solid var(--success-color);
        }


        /* Scrollbar styling for WebKit browsers */
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #2a2a2a; border-radius: var(--border-radius); }
        ::-webkit-scrollbar-thumb { background: var(--primary-color); border-radius: var(--border-radius); }
        ::-webkit-scrollbar-thumb:hover { background: var(--primary-hover-color); }

        /* To hide the main container when admin panel is active */
        body.admin-panel-active .container#main-container {
            filter: blur(5px); /* Optional: blur background */
            pointer-events: none;
            user-select: none;
        }
    </style>
</head>
<body>
    <div class="gtranslate_wrapper"></div>
    <script>window.gtranslateSettings = {"default_language":"en","native_language_names":true,"detect_browser_language":true,"wrapper_selector":".gtranslate_wrapper"}</script>
    <!-- Here is the language icon stuff -->
    <script src="https://cdn.gtranslate.net/widgets/latest/float.js" defer></script>
    <style>
      dark-mode-toggle {
        position: fixed;
        top: 16px;   /* distance from top */
        right: 16px; /* distance from right */
        z-index: 1000; /* make sure it’s on top */
      }
    </style>
    <div class="container" id="main-container">
        <h1>Shorten Your Link</h1>

        <?php if ($error): ?>
            <p class="message error"><?=htmlspecialchars($error)?></p>
        <?php endif; ?>
        <?php if ($success && $shortUrl): ?>
            <p class="message success"><?=htmlspecialchars($success)?></p>
            <p class="short-url-display" id="short-url-result" title="Click to copy"><?=htmlspecialchars($shortUrl)?></p>
        <?php endif; ?>

        <form method="POST" id="shorten-form" autocomplete="off">
            <input type="url" name="url" id="url-input" placeholder="Enter long URL (e.g., https://example.com)" required />
            <input type="text" name="custom" id="custom-input" placeholder="Custom alias (optional, 3-20 characters: letters, numbers, _, -)" pattern="[a-zA-Z0-9_-]{3,20}" title="3-20 characters: letters, numbers, _, or -" />
            <button type="submit">Shorten</button>
        </form>
    </div>

    <div class="modal-overlay" id="admin-login-modal" aria-hidden="true">
        <div class="modal-content">
            <h2>Admin Login</h2>
            <form id="admin-login-form" autocomplete="off">
                <input type="text" name="username" id="admin-username" placeholder="Username" required />
                <input type="password" name="password" id="admin-password" placeholder="Password" required />
                <p class="message error" id="login-error-message" style="display:none;"></p>
                <button type="submit">Login</button>
            </form>
        </div>
    </div>

    <div id="admin-panel" aria-hidden="true">
        <div id="admin-panel-content">
            <header>
                <h2>Admin Dashboard (<span id="current-admin-user">Not Logged In</span>)</h2>
                <button id="logout-btn">Logout</button>
            </header>

            <section id="urls-section">
                <h3>Manage URLs (<span id="url-count">0</span>)</h3>
                <button id="clear-urls-btn" class="admin-action-button">Clear All URLs</button>
                <ul id="url-list">
                    </ul>
            </section>

            <section id="blacklist-section">
                <h3>IP Blacklist (<span id="blacklist-count">0</span>)</h3>
                <div class="admin-input-group">
                    <input type="text" id="blacklist-ip-input" placeholder="Enter IP to blacklist (e.g., 192.168.1.1)" pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}$" title="Enter a valid IPv4 address (e.g., 192.168.1.1)" />
                    <button id="add-blacklist-btn">Add IP</button>
                </div>
                <p class="admin-message" id="blacklist-message"></p>
                <ul id="blacklist-list">
                    </ul>
            </section>

            <section id="admin-accounts-section">
                <h3>Manage Admin Accounts (<span id="admin-count">0</span>)</h3>
                <h4>Add New Admin</h4>
                <div class="admin-input-group">
                    <input type="text" id="new-admin-username-input" placeholder="New admin username" />
                    <input type="password" id="new-admin-password-input" placeholder="New admin password (min 8 chars, strong)" required />
                    <input type="password" id="confirm-new-admin-password-input" placeholder="Confirm new password" required />
                    <button id="add-admin-btn">Add Admin</button>
                </div>
                <p class="admin-message" id="add-admin-message"></p>
                <ul id="admin-list">
                    </ul>
            </section>

            <section id="admin-profile-section">
                <h3>Your Admin Profile</h3>
                <h4>Change Username</h4>
                <div class="admin-input-group">
                    <input type="password" id="change-username-password" placeholder="Current password" required />
                    <input type="text" id="change-username-new" placeholder="New username" />
                    <button id="change-username-btn">Change Username</button>
                </div>
                <p class="admin-message" id="change-username-message"></p>

                <h4>Change Password</h4>
                <div class="admin-input-group">
                    <input type="password" id="change-password-current" placeholder="Current password" required />
                    <input type="password" id="change-password-new" placeholder="New password (min 8 chars, strong)" required />
                    <button id="change-password-btn">Change Password</button>
                </div>
                <p class="admin-message" id="change-password-message"></p>
            </section>

        </div>
    </div>

<script>
(() => {
    // Konami code sequence for admin access
    const konamiCodeSequence = ['ArrowUp', 'ArrowUp', 'ArrowDown', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'ArrowLeft', 'ArrowRight', 'b', 'a'];
    let konamiIndex = 0;

    // DOM element references
    const adminLoginModal = document.getElementById('admin-login-modal');
    const adminLoginForm = document.getElementById('admin-login-form');
    const loginErrorMessage = document.getElementById('login-error-message');
    const adminPanel = document.getElementById('admin-panel');
    const currentAdminUserSpan = document.getElementById('current-admin-user');

    // Admin panel specific message displays
    const blacklistMessage = document.getElementById('blacklist-message');
    const addAdminMessage = document.getElementById('add-admin-message');
    const changeUsernameMessage = document.getElementById('change-username-message');
    const changePasswordMessage = document.getElementById('change-password-message');

    // Helper function to display temporary messages in admin sections
    function showAdminMessage(element, type, message, duration = 3000) {
        element.textContent = message;
        // Ensure class is correctly set (e.g., 'admin-message error' or 'admin-message success')
        element.className = `admin-message ${type}`; 
        element.style.display = 'block';

        setTimeout(() => {
            element.style.display = 'none';
            element.textContent = '';
            element.className = 'admin-message'; // Reset class after hiding
        }, duration);
    }

    // Modal control functions
    function toggleModal(modalElement, show) {
        if (show) {
            modalElement.classList.add('active');
            modalElement.setAttribute('aria-hidden', 'false');
        } else {
            modalElement.classList.remove('active');
            modalElement.setAttribute('aria-hidden', 'true');
        }
    }

    function openAdminLogin() {
        toggleModal(adminLoginModal, true);
        document.getElementById('admin-username').focus();
    }

    function closeAdminLogin() {
        toggleModal(adminLoginModal, false);
        loginErrorMessage.style.display = 'none';
        adminLoginForm.reset(); // Clear form fields
    }

    function openAdminPanel() {
        toggleModal(adminPanel, true);
        document.body.classList.add('admin-panel-active'); // Applies blur/pointer-events: none to main content
        fetchAdminLists(); // Fetch latest data for admin panel
    }

    function closeAdminPanel() {
        toggleModal(adminPanel, false);
        document.body.classList.remove('admin-panel-active');
        currentAdminUserSpan.textContent = 'Not Logged In'; // Reset username display
    }

    // Konami code keydown listener
    window.addEventListener('keydown', e => {
        if (e.key.toLowerCase() === konamiCodeSequence[konamiIndex].toLowerCase()) {
            konamiIndex++;
            if (konamiIndex === konamiCodeSequence.length) {
                konamiIndex = 0; // Reset index
                if (!adminPanel.classList.contains('active')) { // Only open login if admin panel isn't already active
                    openAdminLogin();
                }
            }
        } else {
            konamiIndex = 0; // Reset if sequence is broken
        }
    });
    
    // Close login modal with Escape key
    window.addEventListener('keydown', e => {
        if (e.key === "Escape") {
            if (adminLoginModal.classList.contains('active')) closeAdminLogin();
        }
    });

    // Close login modal if clicking on the overlay backdrop
    adminLoginModal.addEventListener('click', (e) => {
        if (e.target === adminLoginModal) closeAdminLogin();
    });


    // Admin Login Form Submission
    adminLoginForm.addEventListener('submit', async e => {
        e.preventDefault();
        loginErrorMessage.style.display = 'none'; // Clear previous error
        const formData = new FormData(adminLoginForm);
        formData.append('admin_action', 'login'); // Specify the admin action

        try {
            const res = await fetch('', { method: 'POST', body: formData });
            const data = await res.json(); // Parse JSON response

            if (data.success) {
                closeAdminLogin(); // Hide login modal
                currentAdminUserSpan.textContent = data.data.username || 'Admin'; // Update displayed username
                openAdminPanel(); // Show admin panel
            } else {
                loginErrorMessage.textContent = data.message || 'Login failed. Please try again.';
                loginErrorMessage.style.display = 'block';
            }
        } catch (err) {
            console.error('Login error:', err);
            loginErrorMessage.textContent = 'Network error or server issue. Please check your connection.';
            loginErrorMessage.style.display = 'block';
        }
    });

    // Helper for making AJAX requests to the admin backend
    async function performAdminAction(action, params = {}, messageElement = null) {
        const body = new URLSearchParams();
        body.append('admin_action', action);
        for (const key in params) {
            body.append(key, params[key]);
        }
        try {
            const response = await fetch('', { method: 'POST', body: body });
            if (!response.ok) {
                // Attempt to read server-side error message if available
                const errorData = await response.json().catch(() => null); 
                throw new Error(errorData?.message || `HTTP error! Status: ${response.status}`);
            }
            const result = await response.json(); // Parse JSON response from PHP

            // Display feedback message based on success/failure
            if (result.success && messageElement) {
                showAdminMessage(messageElement, 'success', result.message);
            } else if (!result.success && messageElement) {
                showAdminMessage(messageElement, 'error', result.message);
            }
            return result; // Return the full result for further processing
        } catch (error) {
            console.error('Admin action error:', error);
            if (messageElement) {
                showAdminMessage(messageElement, 'error', `Error: ${error.message || 'Request failed. Check browser console for details.'}`);
            } else {
                alert(`Error: ${error.message || 'Request failed. Check browser console for details.'}`);
            }
            return { success: false, message: error.message || 'Request failed.' };
        }
    }

    // --- Dynamic List Updaters ---
    // Updates the list of shortened URLs in the admin panel
    function updateUrlList(urls) {
        const listEl = document.getElementById('url-list');
        const countEl = document.getElementById('url-count');
        listEl.innerHTML = ''; // Clear existing list items
        countEl.textContent = Object.keys(urls).length; // Update count display

        if (Object.keys(urls).length === 0) {
            listEl.innerHTML = '<li>No URLs shortened yet.</li>';
            return;
        }

        // Iterate and create list items for each URL
        for (const [code, url] of Object.entries(urls)) {
            const li = document.createElement('li');
            li.innerHTML = `
                <div style="flex-grow: 1;">
                    <strong>${escapeHTML(code)}</strong> &rarr; 
                    <a href="${escapeHTML(url)}" target="_blank" rel="noopener noreferrer">${escapeHTML(url)}</a>
                </div>
                <button class="remove-btn delete-url-btn" data-code="${escapeHTML(code)}" title="Delete this URL">Delete</button>
            `;
            listEl.appendChild(li);
        }
    }

    // Updates the IP blacklist in the admin panel
    function updateBlacklist(blacklist) {
        const listEl = document.getElementById('blacklist-list');
        const countEl = document.getElementById('blacklist-count');
        listEl.innerHTML = '';
        countEl.textContent = blacklist.length;

        if (blacklist.length === 0) {
            listEl.innerHTML = '<li>IP blacklist is empty.</li>';
            return;
        }

        blacklist.forEach(ip => {
            const li = document.createElement('li');
            li.innerHTML = `
                <div style="flex-grow: 1;">${escapeHTML(ip)}</div>
                <button class="remove-btn remove-blacklist-btn" data-ip="${escapeHTML(ip)}" title="Remove this IP from blacklist">Remove</button>
            `;
            listEl.appendChild(li);
        });
    }

    // Updates the list of admin accounts
    function updateAdminList(admins) {
        const listEl = document.getElementById('admin-list');
        const countEl = document.getElementById('admin-count');
        listEl.innerHTML = '';
        countEl.textContent = admins.length;

        if (admins.length === 0) {
            listEl.innerHTML = '<li>No admin users found. This should not happen (at least one admin must exist).</li>';
            return;
        }
        
        // Get the current logged-in admin's username from the UI
        const currentAdmin = currentAdminUserSpan.textContent; 

        admins.forEach(user => {
            const li = document.createElement('li');
            let buttonHtml = '';
            // Prevent removing the currently logged-in admin or if only one admin exists
            if (user === currentAdmin || admins.length === 1) { 
                buttonHtml = `<span style="color: var(--text-muted-color); font-size: 0.8em; white-space: nowrap;">`;
                if (user === currentAdmin) {
                    buttonHtml += `(You)`;
                }
                if (admins.length === 1) {
                    buttonHtml += ` (Last Admin)`;
                }
                buttonHtml += `</span>`;
            } else {
                buttonHtml = `<button class="remove-btn remove-admin-btn" data-user="${escapeHTML(user)}" title="Remove this admin account">Remove</button>`;
            }
            li.innerHTML = `
                <div style="flex-grow: 1;">${escapeHTML(user)}</div>
                ${buttonHtml}
            `;
            listEl.appendChild(li);
        });
    }
    
    // Utility function to safely escape HTML to prevent XSS
    function escapeHTML(str) {
        if (str === null || typeof str === 'undefined') return '';
        return str.toString().replace(/[&<>"']/g, function (match) {
            return {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#39;'
            }[match];
        });
    }

    // Client-side password strength validation
    function validatePasswordStrengthClient(password) {
        if (password.length < 8) {
            return 'Password must be at least 8 characters long.';
        }
        if (!/[A-Z]/.test(password)) {
            return 'Password must include at least one uppercase letter.';
        }
        if (!/[a-z]/.test(password)) {
            return 'Password must include at least one lowercase letter.';
        }
        if (!/[0-9]/.test(password)) {
            return 'Password must include at least one number.';
        }
        if (!/[^A-Za-z0-9]/.test(password)) {
            return 'Password must include at least one special character.';
        }
        return ''; // Return empty string if valid
    }

    // Fetches all administrative lists from the server and updates the UI
    async function fetchAdminLists() {
        const data = await performAdminAction('get_lists');
        if (data.success && data.data) {
            updateUrlList(data.data.urls || {});
            updateBlacklist(data.data.blacklist || []);
            updateAdminList(data.data.admins || []);
            currentAdminUserSpan.textContent = data.data.current_user || 'Admin'; // Ensure correct current user is displayed
        }
    }

    // --- Admin Panel Event Listeners ---
    document.getElementById('logout-btn').addEventListener('click', async () => {
        const result = await performAdminAction('logout');
        if (result.success) {
            closeAdminPanel(); // Hide admin panel and reset UI
            alert(result.message); // Inform user of logout
        }
    });

    document.getElementById('clear-urls-btn').addEventListener('click', async () => {
        if (confirm('Are you absolutely sure you want to clear ALL short URLs? This action cannot be undone.')) {
            const result = await performAdminAction('clear_urls');
            if (result.success) {
                updateUrlList(result.data.urls); // Update UI with empty list
                showAdminMessage(blacklistMessage, 'success', result.message); // Using blacklistMessage for general section messages, or add a dedicated one
            }
        }
    });

    // Event delegation for deleting individual URLs
    document.getElementById('url-list').addEventListener('click', async (e) => {
        if (e.target.classList.contains('delete-url-btn')) {
            const code = e.target.dataset.code; // Get the short code from the button's data attribute
            if (confirm(`Are you sure you want to delete the URL with code '${code}'? This cannot be undone.`)) {
                const result = await performAdminAction('delete_url', { code: code });
                if (result.success) {
                    updateUrlList(result.data.urls); // Refresh the URL list
                    showAdminMessage(blacklistMessage, 'success', result.message); // Provide feedback
                }
            }
        }
    });


    document.getElementById('add-blacklist-btn').addEventListener('click', async () => {
        const ipInput = document.getElementById('blacklist-ip-input');
        const ip = ipInput.value.trim();

        if (!ip) {
            showAdminMessage(blacklistMessage, 'error', 'Please enter an IP address.');
            return;
        }
        // Client-side IP validation
        const ipPattern = /^([0-9]{1,3}\.){3}[0-9]{1,3}$/;
        if (!ipPattern.test(ip)) {
            showAdminMessage(blacklistMessage, 'error', 'Invalid IPv4 address format (e.g., 192.168.1.1).');
            return;
        }

        const result = await performAdminAction('add_blacklist', { ip: ip }, blacklistMessage);
        if (result.success) {
            updateBlacklist(result.data.blacklist); // Update list on success
            ipInput.value = ''; // Clear input field
        }
    });

    document.getElementById('blacklist-list').addEventListener('click', async (e) => {
        if (e.target.classList.contains('remove-blacklist-btn')) {
            const ip = e.target.dataset.ip;
            if (confirm(`Are you sure you want to remove IP '${ip}' from the blacklist?`)) {
                const result = await performAdminAction('remove_blacklist', { ip: ip }, blacklistMessage);
                if (result.success) {
                    updateBlacklist(result.data.blacklist); // Refresh blacklist
                }
            }
        }
    });

    document.getElementById('add-admin-btn').addEventListener('click', async () => {
        const usernameInput = document.getElementById('new-admin-username-input');
        const passwordInput = document.getElementById('new-admin-password-input');
        const confirmPasswordInput = document.getElementById('confirm-new-admin-password-input');

        const newUsername = usernameInput.value.trim();
        const newPassword = passwordInput.value.trim();
        const confirmPassword = confirmPasswordInput.value.trim();

        if (!newUsername) {
            showAdminMessage(addAdminMessage, 'error', 'New admin username cannot be empty.');
            return;
        }
        
        const passwordValidationMsg = validatePasswordStrengthClient(newPassword);
        if (passwordValidationMsg) {
            showAdminMessage(addAdminMessage, 'error', passwordValidationMsg);
            return;
        }

        if (newPassword !== confirmPassword) {
            showAdminMessage(addAdminMessage, 'error', 'New passwords do not match.');
            return;
        }

        const result = await performAdminAction('add_admin', { 
            new_username: newUsername, 
            new_password: newPassword, 
            confirm_password: confirmPassword 
        }, addAdminMessage);

        if (result.success) {
            updateAdminList(result.data.admins); // Refresh admin list
            // Clear input fields
            usernameInput.value = '';
            passwordInput.value = '';
            confirmPasswordInput.value = '';
        }
    });

    document.getElementById('admin-list').addEventListener('click', async (e) => {
        if (e.target.classList.contains('remove-admin-btn')) {
            const user = e.target.dataset.user;
            if (confirm(`Are you sure you want to remove admin user '${user}'? This cannot be undone.`)) {
                const result = await performAdminAction('remove_admin', { del_username: user }, addAdminMessage);
                if (result.success) {
                    updateAdminList(result.data.admins); // Refresh admin list
                }
            }
        }
    });

    document.getElementById('change-username-btn').addEventListener('click', async () => {
        const currentPasswordInput = document.getElementById('change-username-password');
        const newUsernameInput = document.getElementById('change-username-new');

        const currentPassword = currentPasswordInput.value.trim();
        const newUsername = newUsernameInput.value.trim();

        if (!currentPassword) {
            showAdminMessage(changeUsernameMessage, 'error', 'Please enter your current password.');
            return;
        }
        if (!newUsername) {
            showAdminMessage(changeUsernameMessage, 'error', 'New username cannot be empty.');
            return;
        }
        
        const result = await performAdminAction('change_username', { 
            current_password: currentPassword, 
            new_username: newUsername 
        }, changeUsernameMessage);

        if (result.success) {
            currentAdminUserSpan.textContent = result.data.current_user; // Update displayed username in header
            updateAdminList(result.data.admins); // Refresh admin list to reflect username change
            currentPasswordInput.value = '';
            newUsernameInput.value = '';
        }
    });

    document.getElementById('change-password-btn').addEventListener('click', async () => {
        const currentPasswordInput = document.getElementById('change-password-current');
        const newPasswordInput = document.getElementById('change-password-new');
        // Removed confirmNewPasswordInput

        const currentPassword = currentPasswordInput.value.trim();
        const newPassword = newPasswordInput.value.trim();

        if (!currentPassword || !newPassword) {
            showAdminMessage(changePasswordMessage, 'error', 'Both current and new password fields are required.');
            return;
        }
        
        const passwordValidationMsg = validatePasswordStrengthClient(newPassword);
        if (passwordValidationMsg) {
            showAdminMessage(changePasswordMessage, 'error', passwordValidationMsg);
            return;
        }

        const result = await performAdminAction('change_password', { 
            current_password: currentPassword, 
            new_password: newPassword 
        }, changePasswordMessage);

        if (result.success) {
            currentPasswordInput.value = '';
            newPasswordInput.value = '';
        }
    });


    // Copy short URL to clipboard functionality
    const shortUrlResult = document.getElementById('short-url-result');
    if (shortUrlResult) {
        shortUrlResult.addEventListener('click', () => {
            const textToCopy = shortUrlResult.textContent;
            navigator.clipboard.writeText(textToCopy).then(() => {
                // Visual feedback for copying
                shortUrlResult.style.backgroundColor = 'var(--success-color)';
                shortUrlResult.style.borderColor = 'var(--success-color)';
                setTimeout(() => {
                    shortUrlResult.style.backgroundColor = ''; // Revert background
                    shortUrlResult.style.borderColor = 'var(--primary-color)'; // Revert border
                }, 1000);
            }).catch(err => {
                console.error('Failed to copy text: ', err);
                alert('Failed to copy URL to clipboard. Please copy manually.');
            });
        });
    }

})();
</script>
</body>
</html>