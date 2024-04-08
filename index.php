<?php
session_start();

if (!isset($_SESSION["user"])) {
   header("Location: login.php");
   exit();
}


$role = $_SESSION["user"]["role"];

if ($role === "admin") {
    header("Location: adminhome.php");
    exit();
} elseif ($role === "teacher") {
    header("Location: teachers.php");
    exit();
} elseif ($role === "student") {
    header("Location: students.php");
    exit();
} elseif ($role === "ICTteacher") {
    header("Location: ICTTEACHER11home.php");
    exit();
} elseif ($role === "STEMteacher") {
    header("Location: STEMTEACHER11home.php");
    exit();
} elseif ($role === "GASteacher") {
    header("Location: GASTEACHER11home.php");
    exit();
} elseif ($role === "ABMteacher") {
    header("Location: ABMTEACHER11home.php");
    exit();
} elseif ($role === "HUMMSteacher") {
    header("Location: HUMMSTEACHER11home.php");
    exit();
} elseif ($role === "ICT") {
    header("Location: ICT11home.php");
    exit();
} elseif ($role === "STEM") {
    header("Location: STEM11home.php");
    exit();
} elseif ($role === "GAS") {
    header("Location: GAS11home.php");
    exit();
} elseif ($role === "ABM") {
    header("Location: ABM11home.php");
    exit();
} elseif ($role === "Humms") {
    header("Location: HUMMS11home.php");
    exit();
} elseif ($role === "ICTteacher12") {
    header("Location: ICTTEACHER12home.php");
    exit();
} elseif ($role === "STEMteacher12") {
    header("Location: STEMTEACHER12home.php");
    exit();
} elseif ($role === "GASteacher12") {
    header("Location: GASTEACHER12home.php");
    exit();
} elseif ($role === "ABMteacher12") {
    header("Location: ABMTEACHER12home.php");
    exit();
} elseif ($role === "HUMMSteacher12") {
    header("Location: HUMMSTEACHER12home.php");
    exit();
} elseif ($role === "ICT12") {
    header("Location: ICT12home.php");
    exit();
} elseif ($role === "STEM12") {
    header("Location: STEM12home.php");
    exit();
} elseif ($role === "GAS12") {
    header("Location: GAS12home.php");
    exit();
} elseif ($role === "ABM12") {
    header("Location: ABM12home.php");
    exit();
} elseif ($role === "Humms12") {
    header("Location: HUMMS12home.php");
    exit();
}

header("Location: login.php");
exit();
?>
