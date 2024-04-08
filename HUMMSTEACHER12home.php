
<?php
session_start();

// Check if the user is logged in
if (!isset($_SESSION['user'])) {
    header("Location: index.php");
    exit();
}

// Include database connection
require_once "database.php";

$user_id = $_SESSION['user']['id']; // Assuming 'id' is the primary key of the users table
$sql = "SELECT full_name, role FROM users WHERE id = ?";
$stmt = mysqli_prepare($conn, $sql);
if ($stmt) {
    mysqli_stmt_bind_param($stmt, "i", $user_id);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_bind_result($stmt, $full_name, $selected_role);
    mysqli_stmt_fetch($stmt);
    mysqli_stmt_close($stmt);
} else {
    $full_name = "Unknown"; // Default value if unable to fetch full name
    $selected_role = "Unknown"; // Default value if unable to fetch selected role
}
if (!isset($_SESSION['user'])) {
    header("Location: login.php"); 
    exit();
}

$allowedRoles = array('ICTteacher12', 'ABMteacher12', 'HUMMSteacher12','STEMteacher12','GASteacher12');
if (!in_array($_SESSION['user']['role'], $allowedRoles)) {
    header("Location: index.php");  
    exit();
}


$roleHomePageMap = [
    'ICTteacher' => 'ICTTEACHER11home.php',
    'ABMteacher' => 'ABMTEACHER11home.php',
    'HUMMSteacher' => 'HUMMSTEACHER11home.php',
    'STEMteacher' => 'STEM11TEACHERhome.php',
    'GASteacher' => 'GAS11TEACHERhome.php',
    
];


if (array_key_exists($_SESSION['user']['role'], $roleHomePageMap)) {
    
    $homePageURL = $roleHomePageMap[$_SESSION['user']['role']];
} else {
   
    echo "No home page found for the given role.";
}

$roleUrls = array(
    'ICTTEACHER' => array(
        'handoutict11.php',
        'ICTTEACHER11home.php'
    ),
    'ABMTEACHER' => array(
        'handoutabm11.php',
        'ABMTEACHER11home.php'
    ),
    'GASteacher' =>  array(
        'gasupload.php',
        'GASTEACHER11home.php'
    ),
    'HUMMSteacher' =>  array(
        'hummsupload.php',
        'HUMSS11TEACHERhome.php'
    ),
    'ICTTEACHER12' => array(
        'handoutict12.php',
        'ICTTEACHER12home.php'
    ),
    'ABMTEACHER12' => array(
        'handoutabm12.php',
        'ABMTEACHER12home.php'
    ),
    'GASteacher12' =>  array(
        'handoutgas12.php',
        'GASTEACHER12home.php'
    ),
    'HUMMSteacher12' =>  array(
        'handouthumms12.php',
        'HUMSS12TEACHERhome.php'
    ),
    // Add more roles and URLs as needed
);


// Check if the user is logged in and their role is set
if (isset($_SESSION['user'], $_SESSION['user']['role'])) {
    // Get the role of the logged-in user
    $role = strtoupper($_SESSION['user']['role']); // Convert to uppercase

    // Check if the role exists in the role URLs array
    if (array_key_exists($role, $roleUrls)) {
        // Get the corresponding URLs for the role
        $roleUrlsForUser = $roleUrls[$role];
    } else {
        // Default URLs if role is not found
        $roleUrlsForUser = array('#', '#'); // Default URLs
    }
} else {
    // Default URLs if user is not logged in or role is not set
    $roleUrlsForUser = array('#', '#'); // Default URLs
}

if (isset($_GET['delete_image'])) {
    $imageToDelete = $_GET['delete_image'];
  
    include "handoutdb.php";
   
    $deleteQuery = "DELETE FROM handoutict11 WHERE image_url = '$imageToDelete'";
    if (mysqli_query($conn, $deleteQuery)) {
        if (unlink("uploads/$imageToDelete")) {
            header("Location: handoutict11.php");
            exit();
        } else {
            echo "Failed to delete the file from the server.";
        }
    } else {
        echo "Failed to delete the image from the database.";
    }
}
?> 
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Humanities and Social Sciences 12</title>
    <link
      rel="stylesheet"
      href="https://maxst.icons8.com/vue-static/landings/line-awesome/line-awesome/1.3.0/css/line-awesome.min.css"
    />
    <link
      rel="stylesheet"
      href="https://maxst.icons8.com/vue-static/landings/line-awesome/font-awesome-line-awesome/css/all.min.css"
    />
    <link rel="stylesheet" href="adminhome.css" />
    <link rel="stylesheet" href="handout.css" />
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
            <a href="" class="">
                <span class="las la-igloo"></span> <span>Dashboard</span>
            </a>
        </li>
        <li>
            <a href="handout1.php" class="active">
                <span class="las la-file"></span>
                <span>Handout 1 and 2</span>
            </a>
        </li>
        <li>
            <a href="handout2.php">
                <span class="las la-file"></span>
                <span>Handout 3 and 4</span>
            </a>
        </li>
        <li>
            <a href="handout3.php">
                <span class="las la-file"></span>
                <span>Handout 5 and 6</span>
            </a>
        </li>
        <li>
            <a href="<?php echo $roleUrlsForUser[0]; ?>">
                <span class="las la-file"></span>
                <span>Unique Subs</span>
            </a>
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
      