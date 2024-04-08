
<?php
session_start();

// Check if the user is logged in
if (!isset($_SESSION['user'])) {
    header("Location: index.php");
    exit();
}

// Include database connection
require_once "database.php";

// Fetch the full name of the logged-in user
$user_id = $_SESSION['user']['id']; // Assuming 'id' is the primary key of the users table
$sql = "SELECT full_name FROM users WHERE id = ?";
$stmt = mysqli_prepare($conn, $sql);
if ($stmt) {
    mysqli_stmt_bind_param($stmt, "i", $user_id);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_bind_result($stmt, $full_name);
    mysqli_stmt_fetch($stmt);
    mysqli_stmt_close($stmt);
} else {
    $full_name = "Unknown"; // Default value if unable to fetch full name
}

// Close the database connection
mysqli_close($conn);
?>
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>STEM 11</title>
    <link
      rel="stylesheet"
      href="https://maxst.icons8.com/vue-static/landings/line-awesome/line-awesome/1.3.0/css/line-awesome.min.css"
    />
    <link
      rel="stylesheet"
      href="https://maxst.icons8.com/vue-static/landings/line-awesome/font-awesome-line-awesome/css/all.min.css"
    />
    <link rel="stylesheet" href="adminhome.css" />
  </head>
  <body>
    <input type="checkbox" id="nav-toggle" />
    <div class="sidebar">
      <div class="sidebar-brand">
        <h2><span class="lab la-accusoft"></span><span>EmpowerEDU</span></h2>
      </div>

      <div class="sidebar-menu">
        <ul>
          <li>
            <a href="" class="active"
              ><span class="las la-igloo"></span> <span>Dashboard</span></a
            >
          </li>
          <li>
            <a href="1and2.php"
              ><span class="las la-clipboard-list"></span>
              <span>Handout 1 and 2</span></a
            >
          </li>
          <li>
            <a href="3and4.php"
              ><span class="las la-clipboard-list"></span>
              <span>Handout 3 and 4</span></a
            >
          </li>
          <li>
            <a href="5and6.php"
              ><span class="las la-clipboard-list"></span>
              <span>Handout 5 and 6</span></a
            >
          </li>
          <li>
            <a href="stem11subs.php"
              ><span class="las la-clipboard-list"></span>
              <span>Unique subs</span></a
            >
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

 <div class="user-wrapper">
          <img src="img/2.jpg" width="30px" height="30px" alt="" />
          <div>
            <h4><?php echo $full_name; ?></h4>
            <small><?php echo $selected_role; ?></small>
          </div>
          <div>
            <a href="logout.php">
                <span class="material-symbols-outlined" name="logout">
                    logout
                </span>

            </a>
          </div>
        </div>
      </header>

      <div class="main">
        <div class="cards">
          <div class="card-single">
            <div>
              <h1>54</h1>
              <span>Handout 1 and 2</span>
            </div>
            <div>
              <span class="las la-users"></span>
            </div>
          </div>

          <div class="card-single">
            <div>
              <h1>74</h1>
              <span>Handout 3 and 4</span>
            </div>
            <div>
              <span class="las la-clipboard-list"></span>
            </div>
          </div>

          <div class="card-single">
            <div>
              <h1>34</h1>
              <span>Handout 5 and 6</span>
            </div>
            <div>
              <span class="las la-clipboard-list"></span>
            </div>
          </div>
          <div class="card-single">
            <div>
              <h1>10</h1>
              <span>Unique Subs</span>
            </div>
            <div>
              <span class="las la-clipboard-list"></span>
            </div>
          </div>
        </div>
      </div>
    </div>
         <script src="script.js"></script>
         <script type="module" src="https://unpkg.com/ionicons@7.1.0/dist/ionicons/ionicons.esm.js"></script>
         <script nomodule src="https://unpkg.com/ionicons@7.1.0/dist/ionicons/ionicons.js"></script>
             
  </body>
</html>