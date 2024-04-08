<?php
session_start();
if (isset($_SESSION["user"])) {
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration Form</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">
</head>
<body>
    <div class="container">
    <?php
if (isset($_POST["submit"])) {
    $username = $_POST["username"];
    $fullName = isset($_POST["fullname"]) ? $_POST["fullname"] : $username; 
    $email = $_POST["email"];
    $password = $_POST["password"];
    $passwordRepeat = isset($_POST["repeat_password"]) ? $_POST["repeat_password"] : $password; 
    $lrn = $_POST["lrn"]; 

    $passwordHash = password_hash($password, PASSWORD_DEFAULT);

    $errors = array();

    if (empty($fullName) || empty($email) || empty($password) || empty($passwordRepeat)) {
        array_push($errors,"All fields are required");
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        array_push($errors, "Email is not valid");
    }
    if (strlen($password) < 8) {
        array_push($errors,"Password must be at least 8 characters long");
    }
    if ($password !== $passwordRepeat) {
        array_push($errors,"Password does not match");
    }

    require_once "database.php";

    $role = "";
    $sql = "SELECT role FROM registrar WHERE lrn = ?";
    $stmt = mysqli_stmt_init($conn);
    if (mysqli_stmt_prepare($stmt, $sql)) {
        mysqli_stmt_bind_param($stmt, "s", $lrn);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_bind_result($stmt, $role);
        mysqli_stmt_fetch($stmt);
        mysqli_stmt_close($stmt);
    } else {
        array_push($errors, "Error: " . mysqli_error($conn));
    }

    if (empty($role)) {
        array_push($errors, "LRN does not exist in registrar table or role is not assigned.");
    }

    if (count($errors) > 0) {
        foreach ($errors as $error) {
            echo "<div class='alert alert-danger'>$error</div>";
        }
    } else {
        $sql = "INSERT INTO users (full_name, email, password, lrn, role) VALUES (?, ?, ?, ?, ?)";
        $stmt = mysqli_stmt_init($conn);

        if (mysqli_stmt_prepare($stmt, $sql)) {
            mysqli_stmt_bind_param($stmt, "sssss", $fullName, $email, $passwordHash, $lrn, $role);
            mysqli_stmt_execute($stmt);

            echo "<div class='alert alert-success'>Registration complete. You are now registered.</div>";
            echo '<a href="login.php" class="btn btn-primary">Back</a>';
        } else {
            echo "<div class='alert alert-danger'>Error: " . mysqli_error($conn) . "</div>";
        }

        mysqli_stmt_close($stmt);
    }

    mysqli_close($conn);
}
?>

    </div>
</body>
</html>
