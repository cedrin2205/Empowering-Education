<?php
session_start();

if (isset($_POST["change_password"])) {
    $lrn = $_POST["lrn"];
    $new_password = $_POST["new_password"];

    require_once "database.php";

    $sql = "SELECT * FROM users WHERE lrn = ?";
    $stmt = mysqli_stmt_init($conn);
    if ($prepareStmt = mysqli_stmt_prepare($stmt, $sql)) {
        mysqli_stmt_bind_param($stmt, "s", $lrn);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);
        $rowCount = mysqli_stmt_num_rows($stmt);
        mysqli_stmt_close($stmt);

        if ($rowCount > 0) {
            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
            $update_sql = "UPDATE users SET password = ? WHERE lrn = ?";
            $update_stmt = mysqli_stmt_init($conn);
            if ($update_prepare_stmt = mysqli_stmt_prepare($update_stmt, $update_sql)) {
                mysqli_stmt_bind_param($update_stmt, "ss", $hashed_password, $lrn);
                mysqli_stmt_execute($update_stmt);
                mysqli_stmt_close($update_stmt);

                echo "Password updated successfully!";
            } else {
                echo "Error updating password: " . mysqli_error($conn);
            }
        } else {
            echo "LRN not found in the database!";
        }
    } else {
        echo "Error: " . mysqli_error($conn);
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Change Password</title>
</head>
<body>
    <form>
    <a href="login.php">Go back</a>
    </form>
    <center><h2>Change Password</h2>
    <form action="" method="post">
        <div>
            <label for="lrn">LRN:</label>
            <input type="text" id="lrn" name="lrn" required>
        </div>
        <div>
            <label for="new_password">New Password:</label>
            <input type="password" id="new_password" name="new_password" required>
        </div>
        <div>
            <button type="submit" name="change_password">Change Password</button>
        </div>
    </form>
</center>
</body>
</html>
