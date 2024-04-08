<?php
session_start();

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

if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'admin') {
    header("Location: index.php"); 
    exit();
}

if (isset($_POST["submit"])) {
    $lrn = $_POST["lrn"];
    $selectedRole = $_POST["role"];

    if (empty($lrn) || empty($selectedRole)) {
        $_SESSION['error'] = "Please Select A Strand.";
        header("Location: users.php?error=emptyfields");
        exit();
    }

    require_once "database.php";

    // Update the role for the user in the database
    $sql = "UPDATE users SET role = ? WHERE lrn = ?";
    $stmt = mysqli_stmt_init($conn);
    if (mysqli_stmt_prepare($stmt, $sql)) {
        mysqli_stmt_bind_param($stmt, "ss", $selectedRole, $lrn);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_close($stmt);
    } else {
        die("Error: " . mysqli_error($conn));
    }

    mysqli_close($conn);

    // Redirect back to users.php after updating the role
    header("Location: users.php");
    exit();
} else {
    header("Location: users.php?error=invalidsubmit");
    exit();
}
?>
