<?php
session_start();

// Check if the user is logged in and is an admin
if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'admin') {
    header("Location: index.php");
    exit();
}

// Include database connection
require_once "database.php";

// Array of available roles
$roles = array(
    'standby' => 'Standby',
    'Humms' => 'Humms11',
    'ABM' => 'ABM11',
    'ICT' => 'ICT11',
    'STEM' => 'STEM11',
    'GAS' => 'GAS11',
    'Humms12' => 'Humms12',
    'ABM12' => 'ABM12',
    'ICT12' => 'ICT12',
    'STEM12' => 'STEM12',
    'GAS12' => 'GAS12',
    'admin' => 'Admin',
    'ICTteacher' => 'ICTteacher11',
    'ABMteacher' => 'ABMteacher11',
    'GASteacher' => 'GASteacher11',
    'STEMteacher' => 'STEMteacher11',
    'HUMMSteacher' => 'HUMMSteacher11',
    'ICTteacher12' => 'ICTteacher12',
    'HUMMSteacher12' => 'HUMMSteacher12',
    'ABMteacher12' => 'ABMteacher12',
    'STEMteacher12' => 'STEMteacher12',
    'GASteacher12' => 'GASteacher12'
    // Add more roles as needed
);

// Handle form submission for updating user roles
if (isset($_POST["submit"])) {
    $lrn = $_POST["lrn"];
    $selectedRole = $_POST["role"];

    // Validate LRN and selected role
    if (empty($lrn) || empty($selectedRole)) {
        $_SESSION['error'] = "Please select a role.";
    } else {
        // Update the role for the user in the database
        $sql = "UPDATE users SET role = ? WHERE lrn = ?";
        $stmt = mysqli_prepare($conn, $sql);
        if ($stmt) {
            mysqli_stmt_bind_param($stmt, "ss", $selectedRole, $lrn);
            mysqli_stmt_execute($stmt);
            mysqli_stmt_close($stmt);
            $_SESSION['success'] = "Role updated successfully.";
        } else {
            $_SESSION['error'] = "Error: " . mysqli_error($conn);
        }
    }

    // Redirect back to users.php
    header("Location: users.php");
    exit();
}

// Fetch data from the users table
$sql = "SELECT lrn, email, role FROM users";
$result = mysqli_query($conn, $sql);

// Close the database connection
mysqli_close($conn);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Users Table</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
    <a href="adminhome.php" class="btn btn-secondary">Back</a> <!-- Back button -->
    <div class="container mt-4">
        <h2 style="font-size: medium;">Users Table</h2>
        <?php if (isset($_SESSION['error'])) : ?>
            <div class="alert alert-danger"><?php echo $_SESSION['error']; ?></div>
            <?php unset($_SESSION['error']); ?>
        <?php endif; ?>
        <?php if (isset($_SESSION['success'])) : ?>
            <div class="alert alert-success"><?php echo $_SESSION['success']; ?></div>
            <?php unset($_SESSION['success']); ?>
        <?php endif; ?>
        <table class='table table-striped'>
            <thead>
                <tr>
                    <th>LRN</th>
                    <th>Email</th>
                    <th>Strand (Role)</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php while ($row = mysqli_fetch_assoc($result)) : ?>
                    <tr>
                        <td><?php echo $row['lrn']; ?></td>
                        <td><?php echo $row['email']; ?></td>
                        <td><?php echo $row['role']; ?></td>
                        <td>
                            <form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
                                <input type='hidden' name='lrn' value='<?php echo $row['lrn']; ?>'>
                                <select class='form-select' name='role'>
                                    <option value='' disabled selected>Select a role</option>
                                    <?php foreach ($roles as $role => $displayName) : ?>
                                        <option value='<?php echo $role; ?>'><?php echo $displayName; ?></option>
                                    <?php endforeach; ?>
                                </select>
                                <button type='submit' class='btn btn-primary' name='submit'>Update Role</button>
                            </form>
                        </td>
                    </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
    </div>
</body>
</html>
