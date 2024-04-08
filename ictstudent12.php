
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

    <div class="container">
        <h1>ICT 12 Student</h1>
        <a href="logout.php" class="btn btn-warning">Logout</a>
    </div>
    <div class="gallery">
    <?php 
    include "ictdb12.php";
    $limit = 5; 
    $sql = "SELECT * FROM ictteacher12 ORDER BY id DESC LIMIT $limit";
    $res = mysqli_query($conn, $sql);

    if (mysqli_num_rows($res) > 0) {
        while ($ictteacher12 = mysqli_fetch_assoc($res)) { ?>
            <div class="alb">
                <?php 
                $fileExtension = pathinfo($ictteacher12['image_url'], PATHINFO_EXTENSION);
                if ($fileExtension === 'pdf') {
                  
                    echo '<img src="img/pdficon.png" alt="PDF File">';
                } elseif ($fileExtension === 'doc' || $fileExtension === 'docx') {
                   
                    echo '<img src="img/wordicon.png" alt="Word File">';
                } else {
                
                    echo '<img src="uploads/'.$ictteacher12['image_url'].'" alt="Uploaded Image">';
                }
                ?>
                <p><?php echo $ictteacher12['filename']; ?></p> 
                <a class="download-btn" href="uploads/<?=$ictteacher12['image_url']?>" download="<?=$ictteacher12['image_url']?>">
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
    document.querySelector('.close').addEventListener('click', function() {
        document.querySelector('.image-modal').style.display = 'none';
    });
</script>
</body>
</html>