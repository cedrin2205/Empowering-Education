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

// Debug: Check $_SESSION['user']['role']
echo "User role: " . $_SESSION['user']['role'] . "<br>";

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
    'ICTteacher12' => 'ICTTEACHER12home.php',
    'ABMteacher12' => 'ABMTEACHER12home.php',
    'HUMMSteacher12' => 'HUMMSTEACHER12home.php',
    'STEMteacher12' => 'STEM12TEACHERhome.php',
    'GASteacher12' => 'GAS12TEACHERhome.php',
];

// Debug: Check $roleHomePageMap
echo "Home page URL: " . $roleHomePageMap[$_SESSION['user']['role']] . "<br>";

if (array_key_exists($_SESSION['user']['role'], $roleHomePageMap)) {
    $homePageURL = $roleHomePageMap[$_SESSION['user']['role']];
} else {
    echo "No home page found for the given role.";
}

$roleUrls = [
    'ICTteacher12' => ['handoutict12.php', 'ICTTEACHER12home.php'],
    'ABMTEACHER12' => ['handoutabm12.php', 'ABMTEACHER12home.php'],
    'GASteacher12' => ['handoutgas12.php', 'GASTEACHER12home.php'],
    'HUMMSteacher12' => ['handouthumms12.php', 'HUMSS12TEACHERhome.php'],
    'STEMteacher12' => ['handoutstem12.php', 'STEMTEACHER12home.php']
    // Add more roles and URLs as needed
];

// Check if the user is logged in and their role is set
if (isset($_SESSION['user'], $_SESSION['user']['role'])) {
    // Get the role of the logged-in user
    $role = strtoupper($_SESSION['user']['role']); // Convert to uppercase

    // Debug: Check if the role exists in $roleUrls
    if (array_key_exists($role, $roleUrls)) {
        echo "Role '$role' exists in roleUrls<br>";
        // Get the corresponding URLs for the role
        $roleUrlsForUser = $roleUrls[$role];
    } else {
        echo "Role '$role' does not exist in roleUrls<br>";
        // Default URLs if role is not found
        $roleUrlsForUser = ['#', '#']; // Default URLs
    }
} else {
    // Default URLs if user is not logged in or role is not set
    $roleUrlsForUser = ['#', '#']; // Default URLs
}



if (isset($_GET['delete_image'])) {
    $imageToDelete = $_GET['delete_image'];
  
    include "handoutdb.php";
   
    $deleteQuery = "DELETE FROM handoutict12 WHERE image_url = '$imageToDelete'";
    if (mysqli_query($conn, $deleteQuery)) {
        if (unlink("uploads/$imageToDelete")) {
            header("Location: handoutict12.php");
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
    <title>Unique Subs</title>
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
            <a href="<?php echo $roleUrlsForUser[1]; ?>" class="">
                <span class="las la-igloo"></span> <span>Dashboard</span>
            </a>
        </li>
        <li>
            <a href="handout1.php" class="active">
                <span class="las la-clipboard-list"></span>
                <span>Handout 1 and 2</span>
            </a>
        </li>
        <li>
            <a href="handout2.php">
                <span class="las la-clipboard-list"></span>
                <span>Handout 3 and 4</span>
            </a>
        </li>
        <li>
            <a href="handout3.php">
                <span class="las la-clipboard-list"></span>
                <span>Handout 5 and 6</span>
            </a>
        </li>
        <li>
            <a href="<?php echo $roleUrlsForUser[0]; ?>">
                <span class="las la-clipboard-list"></span>
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
            Unique Subs
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

      <main>
            <div class="">
                <div class="image-modal">
                    <span class="close">&times;</span>
                    <img class="modal-content" id="expandedImg">
                </div>
            </div>
              <div class="" style="
              position: absolute;
              top: 100px;
              left: 400px;
              ">
                <form action="handoutict12upload.php" method="post" enctype="multipart/form-data">
                    <input type="file" name="my_image">
                    <input type="submit" name="submit" value="Upload">
                </form>
            </div>
            <div class="cards">
                <?php 
                include "handoutdb.php";
                $limit = 15; 
                $sql = "SELECT * FROM handoutict12 ORDER BY id DESC LIMIT $limit";
                $res = mysqli_query($conn, $sql);

                if (mysqli_num_rows($res) > 0) {
                    while ($handoutict12 = mysqli_fetch_assoc($res)) { ?>
                        <div class="alb">
                            <?php 
                            $fileExtension = pathinfo($handoutict12['image_url'], PATHINFO_EXTENSION);
                            if ($fileExtension === 'pdf') {
                                echo '<img src="img/pdficon.png" alt="PDF File">';
                            } elseif ($fileExtension === 'doc' || $fileExtension === 'docx') {
                                echo '<img src="img/wordicon.png" alt="Word File">';
                            } elseif ($fileExtension === 'pptx') {
                                echo '<img src="img/pptxicon.png" alt="PowerPoint File">';
                            } elseif ($fileExtension === 'mp4') {
                                echo '<img src="img/mp4icon.png" alt="MP4 File">';
                            } elseif ($fileExtension === 'mp3') {
                                echo '<img src="img/mp3icon.png" alt="MP3 File">';
                            } elseif ($fileExtension === 'gif') {
                                echo '<img src="img/gificon.png" alt="GIF File">';
                            } else {
                                echo '<img src="uploads/'.$handoutict12['image_url'].'" alt="Uploaded Image">';
                            }
                            ?>
                            <p><?php echo $handoutict12['filename']; ?></p>
                            <a class="download-btn" href="uploads/<?=$handoutict12['image_url']?>" download="<?=$handoutict12['image_url']?>">
                                <img src="img/download.png" alt="Download" width="20" height="20">
                            </a>
                            <a href="?delete_image=<?php echo $handoutict12['image_url']; ?>" class="delete-btn">
    <img src="img/delete.png" alt="Delete" width="20" height="20">
</a>
                    </div>
                <?php }
            }
            ?>
</div>
      </main>
    </div>
         <script src="script.js"></script>
         <script type="module" src="https://unpkg.com/ionicons@7.1.0/dist/ionicons/ionicons.esm.js"></script>
         <script nomodule src="https://unpkg.com/ionicons@7.1.0/dist/ionicons/ionicons.js"></script>

         <script>
         function goBack() {
            <?php
            
            echo "window.location.href = '$homePageURL';";
            ?>
        }
    document.addEventListener('click', function (e) {
        if (e.target && e.target.matches('.alb img')) {
            if (!e.target.closest('.download-btn')) {
                document.getElementById('expandedImg').src = e.target.src;
                document.querySelector('.image-modal').style.display = 'block';
            }
        }
    });
    document.querySelectorAll('.delete-btn').forEach(function(btn) {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            var confirmDelete = confirm("Are you sure you want to delete this image?");
            if (confirmDelete) {
            }
        });
    });

    document.querySelector('.close').addEventListener('click', function() {
        document.querySelector('.image-modal').style.display = 'none';
    });
</script>
             
  </body>
</html>