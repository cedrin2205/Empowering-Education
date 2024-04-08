<?php
// Include database connection
include "database.php";

// Initialize variables for notifications
$notification = "";

// Function to sanitize input data
function sanitizeInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

// Function to display notification
function displayNotification($notification) {
    if (!empty($notification)) {
        echo '<div class="row mt-4"><div class="col"><div class="alert alert-success" role="alert">' . $notification . '</div></div></div>';
    }
}

// Check if the form for adding a user was submitted
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['submit_add_user'])) {
    // Sanitize input data
    $lrn = sanitizeInput($_POST['lrn']);
    $role = sanitizeInput($_POST['role']);

    // Prepare and execute SQL query to insert user into registrar table
    $sql = "INSERT INTO registrar (lrn, role) VALUES (?, ?)";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "ss", $lrn, $role);

    if (mysqli_stmt_execute($stmt)) {
        // User added successfully
        $notification = "User added successfully";
    } else {
        // Error adding user
        $notification = "Error adding user: " . mysqli_error($conn);
    }

    // Close the statement
    mysqli_stmt_close($stmt);
}

// Check if the form for updating roles was submitted
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['submit_update_role'])) {
    // Check if roles and LRNs arrays are set
    if (isset($_POST['roles']) && isset($_POST['lrns'])) {
        // Retrieve roles and LRNs from form data
        $roles = $_POST['roles'];
        $lrns = $_POST['lrns'];

        // Prepare and execute SQL query to update roles in registrar table
        $sql = "UPDATE registrar SET role = ? WHERE lrn = ?";
        $stmt = mysqli_prepare($conn, $sql);

        // Initialize an empty array to store success messages
        $successMessages = [];

        // Iterate over each LRN and role
foreach ($lrns as $lrn) {
    // Check if the LRN exists in the roles array
    if (isset($roles[$lrn])) {
        // Sanitize LRN and role
        $lrn = $lrn; // No sanitization needed
        $role = $roles[$lrn]; // No sanitization needed

        // Bind parameters and execute the statement
        mysqli_stmt_bind_param($stmt, "ss", $role, $lrn);
        if (mysqli_stmt_execute($stmt)) {
            // Role updated successfully
            $successMessages[] = "Role for LRN {$lrn} updated successfully";
        } else {
            // Error updating role
            $successMessages[] = "Error updating role for LRN {$lrn}: " . mysqli_error($conn);
        }
    } else {
        // LRN not found in roles array
        $successMessages[] = "LRN {$lrn} not found in roles array";
    }
}

        // Close the statement
        mysqli_stmt_close($stmt);

        // Send the success messages as a notification
        $notification = implode("<br>", $successMessages);
    } else {
        // Roles or LRNs array not provided
        $notification = "Roles or LRNs array not provided";
    }
}

// Fetch data from the registrar table
$sql = "SELECT lrn, role FROM registrar";
$result = mysqli_query($conn, $sql);
?>
<!DOCTYPE html>
<html>
<head>
    <title>Admin Page</title>
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
                <h2 style="font-size: medium;">Add User:</h2>
                <form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
                    <div class="mb-3">
                        <label for="lrn" class="form-label">LRN:</label>
                        <input type="text" class="form-control" id="lrn" name="lrn" required>
                    </div>
                    <div class="mb-3">
                        <label for="role" class="form-label">Role (Strand):</label>
                        <select class="form-select" id="role" name="role" required>
                            <!-- Options for different roles/strands -->
                            <option value="standby">Standby</option>
                            <option value="Humms11">Humms11</option>
                            <option value="ABM11">ABM11</option>
                            <option value="ICT11">ICT11</option>
                            <option value="STEM11">STEM11</option>
                            <option value="GAS11">GAS11</option>
                            <option value="Humms12">Humms12</option>
                            <option value="ABM12">ABM12</option>
                            <option value="ICT12">ICT12</option>
                            <option value="STEM12">STEM12</option>
                            <option value="GAS12">GAS12</option>
                            <option value="admin">Admin</option>
                            <option value="ICTteacher11">ICTteacher11</option>
                            <option value="ABMteacher11">ABMteacher11</option>
                            <option value="GASteacher11">GASteacher11</option>
                            <option value="STEMteacher11">STEMteacher11</option>
                            <option value="HUMMSteacher11">HUMMSteacher11</option>
                            <option value="ICTteacher12">ICTteacher12</option>
                            <option value="HUMMSteacher12">HUMMSteacher12</option>
                            <option value="ABMteacher12">ABMteacher12</option>
                            <option value="STEMteacher12">STEMteacher12</option>
                            <option value="GASteacher12">GASteacher12</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-primary" name="submit_add_user">Add User</button>
                </form>
            </div>
            <div class="col">
                <a href="logout.php" class="btn btn-danger">Logout</a>
                <a href="adminhome.php" class="btn btn-danger">Back</a>
            </div>
        </div>
       <div class="row mt-4">
    <div class="col">
        <h2 style="font-size: medium;">Registrar Table:</h2>
        <form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
            <table class='table table-striped'>
                <tr>
                    <th>LRN</th>
                    <th>Role (Strand)</th>
                    <th>Action</th>
                </tr>
                <?php
                if ($result) {
                    while ($row = mysqli_fetch_assoc($result)) {
                        echo "<tr>";
                        echo "<td>{$row['lrn']}</td>";
                        echo "<td>{$row['role']}</td>";
                        echo "<td>";
                        echo "<input type='hidden' name='lrns[]' value='{$row['lrn']}'>";
                        echo "<select class='form-select' name='roles[{$row['lrn']}]'>";
                        // Add prompt option
                        echo "<option value='' disabled selected>Select a strand to update</option>";
                        // Add options for different roles/strands
                        // You can customize the options as needed
                        echo "<option value='standby'>Standby</option>";
                        echo "<option value='Humms'>Humms11</option>";
                        echo "<option value='ABM'>ABM11</option>";
                        echo "<option value='ICT'>ICT11</option>";
                        echo "<option value='STEM'>STEM11</option>";
                        echo "<option value='GAS'>GAS11</option>";
                        echo "<option value='Humms12'>Humms12</option>";
                        echo "<option value='ABM12'>ABM12</option>";
                        echo "<option value='ICT12'>ICT12</option>";
                        echo "<option value='STEM12'>STEM12</option>";
                        echo "<option value='GAS12'>GAS12</option>";
                        echo "<option value='admin'>Admin</option>";
                        echo "<option value='ICTteacher'>ICTteacher11</option>";
                        echo "<option value='ABMteacher'>ABMteacher11</option>";
                        echo "<option value='GASteacher'>GASteacher11</option>";
                        echo "<option value='STEMteacher'>STEMteacher11</option>";
                        echo "<option value='HUMMSteacher'>HUMMSteacher11</option>";
                        echo "<option value='ICTteacher12'>ICTteacher12</option>";
                        echo "<option value='HUMMSteacher12'>HUMMSteacher12</option>";
                        echo "<option value='ABMteacher12'>ABMteacher12</option>";
                        echo "<option value='STEMteacher12'>STEMteacher12</option>";
                        echo "<option value='GASteacher12'>GASteacher12</option>";
                        // Add more options if necessary
                        echo "</select>";
                        echo "<button type='submit' class='btn btn-primary' name='submit_update_role'>Update Role</button>";
                        echo "</td>";
                        echo "</tr>";

                    }
                    // Close the MySQLi connection
                    mysqli_free_result($result);
                } else {
                    echo "Error in SQL query: " . mysqli_error($conn);
                }
                ?>
            </table>
        </form>
    </div>
</div>
    
    </div>
</body>
</html>

