<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Dashboard</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background-color: #f0f2f5; 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            height: 100vh; 
            margin: 0; 
        }
        .dashboard-card { 
            background: white; 
            padding: 40px; 
            border-radius: 12px; 
            box-shadow: 0 4px 20px rgba(0,0,0,0.08); 
            text-align: center; 
            width: 100%; 
            max-width: 400px; 
        }
        h1 { color: #1c1e21; margin-bottom: 10px; }
        p { color: #606770; margin-bottom: 30px; }
        
        /* Admin Link Style */
        #adminSection {
            display: none; /* Hidden by default */
            margin-bottom: 20px;
            padding: 15px;
            background-color: #fff3cd;
            border: 1px solid #ffeeba;
            border-radius: 8px;
        }
        .admin-link {
            color: #856404;
            text-decoration: none;
            font-weight: bold;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }

        .logout-btn { 
            display: inline-block; 
            padding: 12px 24px; 
            background-color: #007bff; 
            color: white; 
            text-decoration: none; 
            border-radius: 6px; 
            font-weight: 600; 
            transition: background 0.2s; 
        }
        .logout-btn:hover { background-color: #0056b3; }
    </style>
</head>
<body>

    <div class="dashboard-card">
        <div id="adminSection">
            <a href="/admin" class="admin-link">
                <span>🛡️</span> Open Admin Control Panel
            </a>
        </div>

        <h1>Welcome back!</h1>
        <p>You have successfully logged into your account.</p>
        
        <a href="/logout" class="logout-btn">Logout</a>
    </div>

    <script>
        // When the page loads, ask the server who is logged in
        async function checkUserRole() {
            try {
                const response = await fetch('/api/me');
                if (response.ok) {
                    const data = await response.json();
                    
                    // If the user's role is Admin, show the hidden link
                    if (data.role === 'Admin') {
                        document.getElementById('adminSection').style.display = 'block';
                    }
                }
            } catch (err) {
                console.error("Error fetching user data:", err);
            }
        }

        checkUserRole();
    </script>
</body>
</html>
