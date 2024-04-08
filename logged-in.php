<?php
session_start();

function loginUser($email, $password, $conn) {
    $sql = "SELECT lrn FROM users WHERE email = ?";
    $stmt = mysqli_stmt_init($conn);
    if ($prepareStmt = mysqli_stmt_prepare($stmt, $sql)) {
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_bind_result($stmt, $userLRN);
        mysqli_stmt_fetch($stmt);
        mysqli_stmt_close($stmt);

        if ($userLRN) {
            $sql = "SELECT * FROM registrar WHERE lrn = ?";
            $stmt = mysqli_stmt_init($conn);
            if ($prepareStmt = mysqli_stmt_prepare($stmt, $sql)) {
                mysqli_stmt_bind_param($stmt, "s", $userLRN);
                mysqli_stmt_execute($stmt);
                mysqli_stmt_store_result($stmt);
                $rowCount = mysqli_stmt_num_rows($stmt);
                mysqli_stmt_close($stmt);

                if ($rowCount > 0) {
                    $sql = "SELECT id, password, role FROM users WHERE email = ?";
                    $stmt = mysqli_stmt_init($conn);
                    if ($prepareStmt = mysqli_stmt_prepare($stmt, $sql)) {
                        mysqli_stmt_bind_param($stmt, "s", $email);
                        mysqli_stmt_execute($stmt);
                        mysqli_stmt_bind_result($stmt, $userId, $hashedPassword, $userRole);
                        mysqli_stmt_fetch($stmt);

                        if (password_verify($password, $hashedPassword)) {
                            $_SESSION['user'] = [
                                'id' => $userId,
                                'role' => $userRole,
                            ];
                            header("Location: index.php");
                            exit();
                        } else {
                            return "Invalid email or password";
                        }
                    } else {
                        return "Error: " . mysqli_error($conn);
                    }
                } else {
                    return "LRN does not exist in the registrar table";
                }
            } else {
                return "Error: " . mysqli_error($conn);
            }
        } else {
            return "LRN not found for the user";
        }
    } else {
        return "Error: " . mysqli_error($conn);
    }
}

if (isset($_POST["login"])) {
    $email = $_POST["email"];
    $password = $_POST["password"];

    require_once "database.php";

    $loginError = loginUser($email, $password, $conn);

    if ($loginError) {
        echo '<script>';
        echo 'document.addEventListener("DOMContentLoaded", function() {';
        echo 'document.querySelector(".wrapper").classList.add("active-popup");';
        echo '});';
        echo '</script>';
    }
}
?>
<center>
<h2><font color = "red">LRN IS NOT VALID</font></h2>
<center>
<form action="your_action.php" method="post">
<button type="submit" class="button-link">Go Back</button>
        <a href="login.php">Link Text</a>
    </button>
    <style>.button-link {
    background-color: transparent;
    border: none;
    padding: 0;
    text-align: center;
    text-decoration: none;
    cursor: pointer;
}

.button-link a {
    display: inline-block;
    padding: 10px 20px; 
    background-color: #007bff; 
    color: #fff; 
    border-radius: 5px;
    text-decoration: none;
}</style>
</form>
</center>
