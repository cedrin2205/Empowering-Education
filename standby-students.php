<!DOCTYPE html>
<html>
<head>
    <title>Standby Students</title>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Add any necessary CSS links here -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">
</head>
<body>
    <div class="container">
        <div class="row mt-4">
            <div class="col">
                <h2 style="font-size: medium;">Standby Students:</h2>
                <div class="standby-students">
                    <form id="updateForm" method="post">
                        <table class='table table-striped'>
                            <tr>
                                <th>LRN</th>
                                <th>Strand</th>
                                <th>Update</th>
                            </tr>
                            <?php
                            // Establishing connection to the database
                            include "database.php";

                            // Query to fetch standby students based on their role (strand)
                            $sql_standby = "SELECT lrn, role FROM registrar WHERE role = 'standby'";
                            $result_standby = mysqli_query($conn, $sql_standby);

                            if (!$result_standby) {
                                die("Error in SQL query: " . mysqli_error($conn));
                            }

                            if (mysqli_num_rows($result_standby) > 0) {
                                while ($row_standby = mysqli_fetch_assoc($result_standby)) {
                                    $lrn_standby = $row_standby['lrn'];
                                    $role_standby = $row_standby['role'];
                                    ?>
                                    <tr>
                                        <td><?php echo $lrn_standby; ?></td>
                                        <td>
                                            <select class='form-select' name='role' id='strand_<?php echo $lrn_standby; ?>' required>
                                            <option value='standby' <?php if($role_standby == 'standby') echo 'selected'; ?>>Standby</option>
                                            <option value='Humms' <?php if($role_standby == 'Humms') echo 'selected'; ?>>Humms11</option>
                                            <option value='ABM' <?php if($role_standby == 'ABM') echo 'selected'; ?>>ABM11</option>
                                            <option value='ICT' <?php if($role_standby == 'ICT') echo 'selected'; ?>>ICT11</option>
                                            <option value='STEM' <?php if($role_standby == 'STEM') echo 'selected'; ?>>STEM11</option>
                                            <option value='GAS' <?php if($role_standby == 'GAS') echo 'selected'; ?>>GAS11</option>
                                            <option value='Humms12' <?php if($role_standby == 'Humms12') echo 'selected'; ?>>Humms12</option>
                                            <option value='ABM12' <?php if($role_standby == 'ABM12') echo 'selected'; ?>>ABM12</option>
                                            <option value='ICT12' <?php if($role_standby == 'ICT12') echo 'selected'; ?>>ICT12</option>
                                            <option value='STEM12' <?php if($role_standby == 'STEM12') echo 'selected'; ?>>STEM12</option>
                                            <option value='GAS12' <?php if($role_standby == 'GAS12') echo 'selected'; ?>>GAS12</option>
                                            <option value='HUMMSteacher12' <?php if($role_standby == 'HUMMSteacher12') echo 'selected'; ?>>Humms12teacher</option>
                                            <option value='ABMteacher12' <?php if($role_standby == 'ABMteacher12') echo 'selected'; ?>>ABM12teacher</option>
                                            <option value='ICTteacher12' <?php if($role_standby == 'ICTteacher12') echo 'selected'; ?>>ICT12teacher</option>
                                            <option value='STEMteacher12' <?php if($role_standby == 'STEMteacher12') echo 'selected'; ?>>STEM12teacher</option>
                                            <option value='GASteacher12' <?php if($role_standby == 'GASteacher12') echo 'selected'; ?>>GAS12teacher</option>
                                            <option value='HUMMSteacher' <?php if($role_standby == 'HUMMSteacher') echo 'selected'; ?>>Humms11teacher</option>
                                            <option value='ABMteacher' <?php if($role_standby == 'ABMteacher') echo 'selected'; ?>>ABM11teacher</option>
                                            <option value='ICTteacher' <?php if($role_standby == 'ICTteacher') echo 'selected'; ?>>ICT11teacher</option>
                                            <option value='STEMteacher' <?php if($role_standby == 'STEMteacher') echo 'selected'; ?>>STEM11teacher</option>
                                            <option value='GASteacher' <?php if($role_standby == 'GASteacher') echo 'selected'; ?>>GAS11teacher</option>
                                            <option value='admin' <?php if($role_standby == 'admin') echo 'selected'; ?>>admin</option>
                                        </select>
                                        </td>
                                        <td>
                                            <button type="button" class="btn btn-primary" onclick="updateRole('<?php echo $lrn_standby; ?>')">Update</button>
                                        </td>
                                    </tr>
                                    <?php
                                }
                            } else {
                                echo "<tr><td colspan='3'>No standby students found.</td></tr>";
                            }

                            // Close the MySQLi connection after all queries have been executed
                            mysqli_close($conn);
                            ?>
                        </table>
                        <input type="hidden" name="lrn[]" id="lrnInput">
                    </form>
                </div>
                <a href="admin.php" class="btn btn-primary">Back</a>
            </div>
        </div>
    </div>

    <script>
        // Function to set the LRN and submit the form using AJAX
        function updateRole(lrn) {
            var roleSelect = document.getElementById('strand_' + lrn);
            var newRole = roleSelect.value;

            // Create an XMLHttpRequest object
            var xhr = new XMLHttpRequest();

            // Configure the request
            xhr.open('POST', 'update_role.php', true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

            // Define the callback function to handle the response
            xhr.onreadystatechange = function() {
                if (xhr.readyState === XMLHttpRequest.DONE) {
                    if (xhr.status === 200) {
                        // Request was successful, handle the response
                        alert(xhr.responseText); // Display response as an alert
                        // You can update the UI or perform other actions based on the response here
                    } else {
                        // Request failed, handle the error
                        console.error('Request failed:', xhr.status);
                    }
                }
            };

            // Prepare the data to send (LRN and new role)
            var data = 'lrn=' + encodeURIComponent(lrn) + '&role=' + encodeURIComponent(newRole);

            // Send the request with the data
            xhr.send(data);
        }
    </script>
</body>
</html>
