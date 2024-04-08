<!DOCTYPE html>
<html>
<head>
    <title>Users</title>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Add any necessary CSS links here -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">
</head>
<body>
    <!-- Your sidebar or other content -->
    <div class="container">
        <div class="row">
            <div class="col">
                <h2 style="font-size: medium;">Registered Users:</h2>
                <div class="users-students">
                        
                <?php
                    // Establishing connection to the database
                    include "database.php";

                    $sql = "SELECT r.lrn, u.full_name, u.email, u.role FROM registrar r INNER JOIN users u ON r.lrn = u.lrn";
                    $result = mysqli_query($conn, $sql);

                    if (!$result) {
                        die("Error in SQL query: " . mysqli_error($conn));
                    }

                    echo "<table class='table table-striped'>";
                    echo "<tr>";
                    echo "<th>LRN</th>";
                    echo "<th>Username</th>";
                    echo "<th>Email</th>";
                    echo "<th>Strand</th>";
                    echo "</tr>";

                    if (mysqli_num_rows($result) > 0) {
                        while ($row = mysqli_fetch_assoc($result)) {
                            $lrn = $row['lrn'];
                            $full_name = $row['full_name'];
                            $email = $row['email'];
                            $role = $row['role'];

                            echo "<tr>";
                            echo "<td>$lrn</td>";
                            echo "<td>$full_name</td>";
                            echo "<td>$email</td>";
                            echo "<td>$role</td>";
                            echo "</tr>";
                        }
                    } else {
                        echo "<tr><td colspan='3'>No registered users found.</td></tr>";
                    }

                    echo "</table>";

                    // Close the MySQLi connection after all queries have been executed
                    mysqli_close($conn);
                ?>

                <a href="admin.php" class="btn btn-primary">Back</a>

                    </table>
                </div>
            </div>
        </div>
</body>
</html>
