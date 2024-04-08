<?php
session_start();

// Check if user is not logged in or not an admin, redirect to login page
if (!isset($_SESSION["user"]) || $_SESSION["user"]["role"] !== "admin") {
   header("Location: login.php");
   exit();
}

// Your database connection logic
include "database.php"; // Include your database connection file

// Fetch the number of users from the database
$sqlUsers = "SELECT COUNT(*) AS totalUsers FROM users"; // Assuming 'users' is your users table
$resultUsers = mysqli_query($conn, $sqlUsers);
$dataUsers = mysqli_fetch_assoc($resultUsers);
$numberOfUsers = $dataUsers['totalUsers'];

// Fetch the number of LRNs from the database
$sqlLRNs = "SELECT COUNT(*) AS totalLRNs FROM registrar"; // Assuming 'registrar' is your LRNs table
$resultLRNs = mysqli_query($conn, $sqlLRNs);
$dataLRNs = mysqli_fetch_assoc($resultLRNs);
$numberOfLRNs = $dataLRNs['totalLRNs'];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>Admin</title>
    <link rel="stylesheet"
          href="https://maxst.icons8.com/vue-static/landings/line-awesome/line-awesome/1.3.0/css/line-awesome.min.css"/>
    <link rel="stylesheet"
          href="https://maxst.icons8.com/vue-static/landings/line-awesome/font-awesome-line-awesome/css/all.min.css"/>
    <link rel="stylesheet" href="adminhome.css"/>
</head>
<body>
<input type="checkbox" id="nav-toggle"/>
<div class="sidebar">
    <div class="sidebar-brand">
        <h2><span class="lab la-accusoft"></span><span>EmpowerEDU</span></h2>
    </div>

    <div class="sidebar-menu">
        <ul>
            <li>
                <a href="login.php" class="active"><span class="las la-igloo"></span> <span>Home</span></a>
            </li>
            <li>
                <a href="admin.php"><span class="las la-users"></span> <span>ADD-LRN</span></a>
            </li>
             <li>
                <a href="users.php"><span class="las la-circle"></span> <span>Accounts</span></a>
            </li>
            <li>
                <a href="abm11users.php"><span class="las la-circle"></span> <span>ABM 11</span></a>
            </li>
            <li>
                <a href="abm12users.php"><span class="las la-circle"></span> <span>ABM 12</span></a>
            </li>
            <li>
                <a href="gas11users.php"><span class="las la-circle"></span> <span>GAS 11</span></a>
            </li>
            <li>
                <a href="gas12users.php"><span class="las la-circle"></span> <span>GAS 12</span></a>
            </li>
            <li>
                <a href="humss11users.php"><span class="las la-circle"></span> <span>HUMSS 11</span></a>
            </li>
            <li>
                <a href="humss12users.php"><span class="las la-circle"></span> <span>HUMSS 12</span></a>
            </li>
            <li>
                <a href="ict11users.php"><span class="las la-circle"></span> <span>ICT 11</span></a>
            </li>
            <li>
                <a href="ict12users.php"><span class="las la-circle"></span> <span>ICT 12</span></a>
            </li>
            <li>
                <a href="stem11users.php"><span class="las la-circle"></span> <span>STEM 11</span></a>
            </li>
            <li>
                <a href="stem12users.php"><span class="las la-circle"></span> <span>STEM 12</span></a>
            </li>
        </ul>
    </div>
</div>

<div class="main-content">
    <header>
        <h3>
            <div class="header-title">
                <label for="nav-toggle">
                    <span class="las la-bars"></span>
                </label>
                Dashboard
            </div>
        </h3>

        <div class="search-wrapper">
            <span class="las la-search"></span>
            <input type="search" placeholder="Search here"/>
        </div>

        <div class="user-wrapper">
            <img src="img/2.jpg" width="30px" height="30px" alt=""/>
            <div>
                <h4>Registrar</h4>
                <small>Admin</small>
            </div>
        </div>
    </header>

    <div class="main">
        <div class="cards">
            <div class="card-single">
                <div>
                    <h1><?php echo $numberOfUsers; ?></h1> <!-- PHP: Number of users from database -->
                    <span>Registered</span>
                </div>
                <div>
                    <span class="las la-users"></span>
                </div>
            </div>

            <div class="card-single">
                <div>
                    <h1><?php echo $numberOfLRNs; ?></h1> <!-- PHP: Number of LRNs from database -->
                    <span>Pending</span>
                </div>
                <div>
                    <span class="las la-clipboard-list"></span>
                </div>
            </div>
        </div>

                </div>
            </div>
        </div>
    </div>
</div>
            </div>
        </div>
</div>
</div>
<script>
    // Handle clicks on sidebar menu items
    document.querySelectorAll('.sidebar-menu a').forEach(item => {
        item.addEventListener('click', (e) => {
            const isActive = item.classList.contains('active'); // Check if the clicked item is already active

            // Remove active class from all sidebar menu items
            document.querySelectorAll('.sidebar-menu a').forEach(link => {
                link.classList.remove('active');
            });

            // If the clicked item was not already active, add the active class
            if (!isActive) {
                item.classList.add('active');
            }
        });
    });

    // Handle clicks on card items
    document.querySelectorAll('.card-single').forEach(item => {
        item.addEventListener('click', (e) => {
            document.querySelectorAll('.card-single').forEach(card => {
                card.classList.remove('active');
            });
            e.currentTarget.classList.add('active');
        });
    });

</script>
</body>
</html>


