<?php
session_start();

// Include database connection
include "database.php";

// Function to sanitize input data
function sanitizeInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

// Check if the user is logged in and is an admin
if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'admin') {
    header("Location: index.php");
    exit();
}

// Initialize variables for notifications
$notification = "";

// Handle form submission for adding a user to the 'registrar' table
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST["submit_add_registrar"])) {
        $lrn = sanitizeInput($_POST['lrn']);
        $role = "standby-humss11"; // Set role to standby-humss11

        // Check if LRN already exists in users table
        $sql_check = "SELECT * FROM users WHERE lrn = ?";
        $stmt_check = mysqli_prepare($conn, $sql_check);
        mysqli_stmt_bind_param($stmt_check, "s", $lrn);
        mysqli_stmt_execute($stmt_check);
        mysqli_stmt_store_result($stmt_check);
        $num_rows = mysqli_stmt_num_rows($stmt_check);
        mysqli_stmt_close($stmt_check);

        if ($num_rows == 0) {
            // LRN doesn't exist in users table, proceed to insert into registrar table
            $sql = "INSERT INTO registrar (lrn, role) VALUES (?, ?)";
            $stmt = mysqli_prepare($conn, $sql);
            mysqli_stmt_bind_param($stmt, "ss", $lrn, $role);

            if (mysqli_stmt_execute($stmt)) {
                // User added to registrar table successfully
                $notification = "User added to registrar table successfully with role '$role'";
            } else {
                // Error adding user to registrar table
                $notification = "Error adding user to registrar table: " . mysqli_error($conn);
            }

            // Close the statement
            mysqli_stmt_close($stmt);
        } else {
            // LRN already exists in users table
            $notification = "LRN already exists in users table";
        }
    } elseif (isset($_POST["submit_verify_registrar"])) {
        $lrn = sanitizeInput($_POST['lrn']);
        $new_role = "HUMMS"; // Set role to HUMMS

        // Update role in users table
        $sql_update_users = "UPDATE users SET role = ? WHERE lrn = ?";
        $stmt_update_users = mysqli_prepare($conn, $sql_update_users);
        mysqli_stmt_bind_param($stmt_update_users, "ss", $new_role, $lrn);

        if (mysqli_stmt_execute($stmt_update_users)) {
            // Update role in registrar table
            $sql_update_registrar = "UPDATE registrar SET role = ? WHERE lrn = ?";
            $stmt_update_registrar = mysqli_prepare($conn, $sql_update_registrar);
            mysqli_stmt_bind_param($stmt_update_registrar, "ss", $new_role, $lrn);

            if (mysqli_stmt_execute($stmt_update_registrar)) {
                $notification = "Role updated successfully to '$new_role'";
            } else {
                $notification = "Error updating role in registrar table: " . mysqli_error($conn);
            }

            mysqli_stmt_close($stmt_update_registrar);
        } else {
            $notification = "Error updating role in users table: " . mysqli_error($conn);
        }

        mysqli_stmt_close($stmt_update_users);
    } elseif (isset($_POST["submit_delete_user"])) {
        $lrn = sanitizeInput($_POST['lrn']);

        // Delete user from users table
        $sql_delete_user = "DELETE FROM users WHERE lrn = ?";
        $stmt_delete_user = mysqli_prepare($conn, $sql_delete_user);
        mysqli_stmt_bind_param($stmt_delete_user, "s", $lrn);

        if (mysqli_stmt_execute($stmt_delete_user)) {
            $notification = "User deleted successfully from users table";
        } else {
            $notification = "Error deleting user from users table: " . mysqli_error($conn);
        }

        mysqli_stmt_close($stmt_delete_user);

        // Delete user from registrar table
        $sql_delete_registrar = "DELETE FROM registrar WHERE lrn = ?";
        $stmt_delete_registrar = mysqli_prepare($conn, $sql_delete_registrar);
        mysqli_stmt_bind_param($stmt_delete_registrar, "s", $lrn);

        if (mysqli_stmt_execute($stmt_delete_registrar)) {
            $notification = "User deleted successfully from registrar table";
        } else {
            $notification = "Error deleting user from registrar table: " . mysqli_error($conn);
        }

        mysqli_stmt_close($stmt_delete_registrar);
    }
}

// Fetch data from the registrar table for HUMMS role and standby-humss11 role
$sql_humms = "SELECT r.lrn, r.role, CASE WHEN u.lrn IS NULL THEN 'Pending' ELSE 'Registered' END AS registration_status
            FROM registrar r
            LEFT JOIN users u ON r.lrn = u.lrn
            WHERE r.role IN ('HUMMS', 'standby-humss11')";
$result_humms = mysqli_query($conn, $sql_humms);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registrar Table (HUMMS)</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        .btn-verify {
            background-color: green;
            color: white;
        }
        .btn-delete {
            background-color: red;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container mt-4">
        <h2 style="font-size: medium;">Registrar Table (HUMMS)</h2>
        <?php if (!empty($notification)) : ?>
            <div class="alert alert-<?php echo strpos($notification, 'successfully') !== false ? 'success' : 'danger'; ?>"><?php echo $notification; ?></div>
        <?php endif; ?>
        <form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
            <div class="form-group">
                <label for="lrn">LRN:</label>
                <input type="text" class="form-control" id="lrn" name="lrn" required>
            </div>
            <button type="submit" class="btn btn-primary" name="submit_add_registrar">Add User to Registrar</button>
        </form>
        <table class='table table-striped mt-4'>
            <thead>
                <tr>
                    <th>LRN</th>
                    <th>Role</th>
                    <th>Registration Status</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php if(mysqli_num_rows($result_humms) > 0) : ?>
                    <?php while ($row_humms = mysqli_fetch_assoc($result_humms)) : ?>
                        <tr>
                            <td><?php echo $row_humms['lrn']; ?></td>
                            <td><?php echo $row_humms['role']; ?></td>
                            <td><?php echo $row_humms['registration_status']; ?></td>
                            <td>
                                <?php if ($row_humms['role'] !== 'HUMMS') : ?>
                                    <form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
                                        <input type='hidden' name='lrn' value='<?php echo $row_humms['lrn']; ?>'>
                                        <button type='submit' class='btn btn-verify' name='submit_verify_registrar'>Verify</button>
                                    </form>
                                <?php endif; ?>
                                <form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
                                    <input type='hidden' name='lrn' value='<?php echo $row_humms['lrn']; ?>'>
                                    <button type='submit' class='btn btn-delete' name='submit_delete_user'>Delete</button>
                                </form>
                            </td>
                        </tr>
                    <?php endwhile; ?>
                <?php else : ?>
                    <tr><td colspan='4'>No rows found in the registrar table.</td></tr>
                <?php endif; ?>
            </tbody>
        </table>
        <a href="adminhome.php" class="btn btn-secondary">Back</a> <!-- Back button -->
    </div>
</body>
</html>

<?php
// Close the database connection
mysqli_close($conn);
?>
