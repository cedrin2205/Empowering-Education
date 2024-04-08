<?php
session_start();

if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'admin') {
    header("Location: index.php"); 
    exit();
}

if (isset($_POST["submit"])) {
    $lrn = $_POST["lrn"];
    $selectedRole = $_POST["role"];

    if (empty($lrn) || empty($selectedRole)) {
        $_SESSION['error'] = "Please Select A Strand.";
        header("Location: admin.php?error=emptyfields");
        exit();
    }

    require_once "database.php";

   
    $sql = "SELECT * FROM registrar WHERE lrn = ?";
    $stmt = mysqli_stmt_init($conn);
    if (mysqli_stmt_prepare($stmt, $sql)) {
        mysqli_stmt_bind_param($stmt, "s", $lrn);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);
        $rowCount = mysqli_stmt_num_rows($stmt);
        mysqli_stmt_close($stmt);
    } else {
        die("Error: " . mysqli_error($conn));
    }
    if ($rowCount == 0) {
    
        $sql = "INSERT INTO registrar (lrn) VALUES (?)";
        $stmt = mysqli_stmt_init($conn);
        if (mysqli_stmt_prepare($stmt, $sql)) {
            mysqli_stmt_bind_param($stmt, "s", $lrn);
            mysqli_stmt_execute($stmt);
            mysqli_stmt_close($stmt);
        } else {
            die("Error: " . mysqli_error($conn));
        }
    }

    if ($rowCount == 1) {
       
        $sql = "UPDATE registrar SET role = ? WHERE lrn = ?";
        $stmt = mysqli_stmt_init($conn);
        if (mysqli_stmt_prepare($stmt, $sql)) {
            mysqli_stmt_bind_param($stmt, "ss", $selectedRole, $lrn);
            mysqli_stmt_execute($stmt);
            mysqli_stmt_close($stmt);
        } else {
            die("Error: " . mysqli_error($conn));
        }
    } 
    
    
    if ($rowCount == 1) {
     
        $sql = "UPDATE users SET role = ? WHERE lrn = ?";
        $stmt = mysqli_stmt_init($conn);
        if (mysqli_stmt_prepare($stmt, $sql)) {
            mysqli_stmt_bind_param($stmt, "ss", $selectedRole, $lrn);
            mysqli_stmt_execute($stmt);
            mysqli_stmt_close($stmt);
        } else {
            die("Error: " . mysqli_error($conn));
        }
    } 

    mysqli_close($conn);

    header("Location: admin.php");
    exit();
} else {
    header("Location: admin.php?error=invalidsubmit");
    exit();
}
?>
