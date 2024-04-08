<?php
session_start();


if (!isset($_SESSION['user'])) {
    header("Location: login.php");  
    exit();
}


if ($_SESSION['user']['role'] !== 'STEMteacher12') {
    header("Location: index.php");  
    exit();
}


if (isset($_GET['delete_image'])) {
    $imageToDelete = $_GET['delete_image'];


    include "stemdb12.php";

   
    $deleteQuery = "DELETE FROM stemteacher12 WHERE image_url = '$imageToDelete'";
    if (mysqli_query($conn, $deleteQuery)) {
   
        if (unlink("uploads/$imageToDelete")) {
    
            header("Location: stemteacher12.php");
            exit();
        } else {
       
            echo "Failed to delete the file from the server.";
        }
    } else {

        echo "Failed to delete the image from the database.";
    }
}


if (isset($_POST['submit']) && isset($_FILES['my_image'])) {
    include "stemdb12.php"; 

    $img_name = $_FILES['my_image']['name'];
    $img_size = $_FILES['my_image']['size'];
    $tmp_name = $_FILES['my_image']['tmp_name'];
    $error = $_FILES['my_image']['error'];

    if ($error === 0) {
        $allowed_exs = array("jpg", "jpeg", "png", "docx", "doc", "pdf"); 

        $file_ex = pathinfo($img_name, PATHINFO_EXTENSION);
        $file_ex_lc = strtolower($file_ex);

        if (in_array($file_ex_lc, $allowed_exs)) {
            if ($img_size > 10000000000) {
                $em = "Sorry, your file is too large.";
                header("Location: stemteacher12.php?error=$em");
                exit();
            } else {
                $new_img_name = uniqid("IMG-", true) . '.' . $file_ex_lc;
                $img_upload_path = 'uploads/' . $new_img_name;
                move_uploaded_file($tmp_name, $img_upload_path);

                
                $insertQuery = "INSERT INTO stemteacher12 (image_url, filename) VALUES ('$new_img_name', '$img_name')";
                if (mysqli_query($conn, $insertQuery)) {
                   
                    header("Location: stemteacher12.php");
                    exit();
                } else {
                 
                    echo "Failed to insert into database.";
                }
            }
        } else {
            $em = "You can't upload files of this type";
            header("Location: stemteacher12.php?error=$em");
            exit();
        }
    } else {
        $em = "Unknown error occurred!";
        header("Location: stemteacher12.php?error=$em");
        exit();
    }
}


?>