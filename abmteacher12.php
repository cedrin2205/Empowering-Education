<?php
session_start();

if (!isset($_SESSION['user'])) {
    header("Location: login.php"); 
    exit();
}

if ($_SESSION['user']['role'] !== 'ABMteacher12') {
    header("Location: index.php");  
    exit();
}

if (isset($_GET['delete_image'])) {
    $imageToDelete = $_GET['delete_image'];
  
    include "abmdb12.php";
   
    $deleteQuery = "DELETE FROM abmteacher12 WHERE image_url = '$imageToDelete'";
    if (mysqli_query($conn, $deleteQuery)) {
        if (unlink("uploads/$imageToDelete")) {
            header("Location: abmteacher12.php");
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
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">
    <link rel="stylesheet" href="upload.css">
    <style>
        body {
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        .container {
            position: absolute;
            margin-top: -515px;
            position: fixed;
            width: 1500px;
        }
        .contain {
            margin-top: -500px;
            margin-right: -1090px;
            position: fixed;
            background-color: skyblue;
            box-shadow: rgba(100, 100, 111, 0.2) 0px 7px 29px 0px;
        }
        .gallery {
            margin-bottom: 100px;
            margin-left:400px;
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
        }
        .alb {
            position: relative;
            width: 200px;
            height: 200px;
            padding: 5px;
            margin-top: 200px;
        }
        .alb img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        .delete-btn {
            position: absolute;
            top: 5px;
            right: 5px;
            color: white;
        }
        a {
            text-decoration: none;
            color: black;
        }
        .image-modal {
            display: none;
            position: fixed;
            z-index: 1;
            padding-top: 100px;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.9);
            overflow: auto;
        }
        .modal-content {
            z-index: 1;
            margin: auto;
            display: block;
            width: 80%;
            max-width: 30%;
            max-height: 80%;
        }
        .close {
            position: absolute;
            top: 15px;
            right: 35px;
            color: #f1f1f1;
            font-size: 40px;
            font-weight: bold;
            transition: 0.3s;
        }
        .close:hover,
        .close:focus {
            color: #bbb;
            text-decoration: none;
            cursor: pointer;
        }
        .panel{
            height: 100vh;
            width: 400px;
            background-color:#2a52be;
            position: fixed;
            top: 0;
            left: 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding-top: 20px;
            z-index:1;
        }
        .bar{
            position: fixed;
            margin-top:-495px;
            height: 200px;
            width: 1800px;
            padding: 50px;
            background-color: skyblue;
        }
        .delete-btn {
    width: 20px;
    height: 20px;
}
.download-btn img {
    width: 20px; 
    height: 20px; 
    margin-left: 5px; 
}

    </style>
</head>
<body><div class="bar">
</div>
<div class="panel">
    <h2><font color = "yellow">List of ABM 12 Student:</font></h2>

    <?php
     include "database.php";
 
    $role = 'ABM12'; 

    $sql = "SELECT id, full_name FROM users WHERE role = '$role'";
    $users_result = mysqli_query($conn, $sql) or die("Error in SQL query");

    if (mysqli_num_rows($users_result) > 0) {
        while ($user = mysqli_fetch_assoc($users_result)) {
            $full_name = $user['full_name'];
            echo "<p style='font-size: 20px;'>Name: $full_name</p>";

           
        }
    } else {
        echo "No ABM 12 students found.";
    }
    ?>
</div>
    <div class="container">
        <h1>ABM 12 Teacher</h1>
        <a href="logout.php" class="btn btn-warning">Logout</a>
    </div>
    <div class="contain">
        <form action="abmupload12.php" method="post" enctype="multipart/form-data">
            <input type="file" name="my_image">
            <input type="submit" name="submit" value="Upload">
        </form>
    </div>
    <div class="gallery">
    <?php 
    include "abmdb12.php";
    $limit = 5; 
    $sql = "SELECT * FROM abmteacher12 ORDER BY id DESC LIMIT $limit";
    $res = mysqli_query($conn, $sql);

    if (mysqli_num_rows($res) > 0) {
        while ($abmteacher12 = mysqli_fetch_assoc($res)) { ?>
            <div class="alb">
                <?php 
                $fileExtension = pathinfo($abmteacher12['image_url'], PATHINFO_EXTENSION);
                if ($fileExtension === 'pdf') {
                    echo '<img src="img/pdficon.png" alt="PDF File">';
                } elseif ($fileExtension === 'doc' || $fileExtension === 'docx') {
                    echo '<img src="img/wordicon.png" alt="Word File">';
                } else {
                    echo '<img src="uploads/'.$abmteacher12['image_url'].'" alt="Uploaded Image">';
                }
                ?>
                <p><?php echo $abmteacher12['filename']; ?></p>
                <a class="delete-btn" href="abmteacher12.php?delete_image=<?=$abmteacher12['image_url']?>">
                    <img src="img/remove.png" alt="Delete" width="1" height="1">
                </a>
                <a class="download-btn" href="uploads/<?=$abmteacher12['image_url']?>" download="<?=$abmteacher12['image_url']?>">
                    <img src="img/download.png" alt="Download" width="20" height="20">
                </a>
            </div>
        <?php }
    }
    ?>
</div>
    <div class="image-modal">
        <span class="close">&times;</span>
        <img class="modal-content" id="expandedImg">
    </div>
    <script>
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
<script>
                var xhttp = new XMLHttpRequest();
                xhttp.onreadystatechange = function() {
                    if (this.readyState == 4 && this.status == 200) {
                        location.reload();
                    }
                };
                xhttp.open("GET", "abmteacher12.php?mark_as_seen=" + encodeURIComponent(imageUrl), true);
                xhttp.send();

                document.getElementById('expandedImg').src = imageUrl;
                document.querySelector('.image-modal').style.display = 'block';

        document.querySelector('.close').addEventListener('click', function() {
            document.querySelector('.image-modal').style.display = 'none';
        });
    </script>
</body>
</html>
