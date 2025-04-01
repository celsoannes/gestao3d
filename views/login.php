<?php
session_start();
require __DIR__ . '/../config/config.php';

// Verifica se o usuário já está logado
if (isset($_SESSION['usuario_id'])) {
    header("Location: index.php");
    exit;
}

$erro = "";
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = $_POST['email'];
    $senha = $_POST['senha'];
    
    // Verificação simplificada do reCAPTCHA (igual ao teste que funciona)
    if(empty($_POST['g-recaptcha-response'])) {
        $erro = "Por favor, complete a verificação 'Não sou um robô'.";
    } else {
        // Modo de teste - REMOVA ESTA LINHA EM PRODUÇÃO
        $recaptcha_valid = true;
        
        /* DESCOMENTE ESTE BLOCO EM PRODUÇÃO
        $recaptcha_secret = '6Le2ueYqAAAAAA47DNHhMixFJVpFcTMNAo8JerJp';
        $recaptcha_response = $_POST['g-recaptcha-response'];
        
        // Tentativa de verificação (igual ao teste que funciona)
        $url = 'https://www.google.com/recaptcha/api/siteverify?secret='.$recaptcha_secret.'&response='.$recaptcha_response;
        $response = @file_get_contents($url);
        
        if($response === false) {
            $erro = "Não foi possível verificar o reCAPTCHA. Servidor pode estar bloqueando conexões externas.";
        } else {
            $recaptcha = json_decode($response);
            $recaptcha_valid = $recaptcha->success ?? false;
        }
        */
        
        if ($recaptcha_valid) {
            // Processo de autenticação
            try {
                $stmt = $pdo->prepare("SELECT id, nome, senha_hash FROM usuarios WHERE email = ?");
                $stmt->execute([$email]);
                $usuario = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($usuario && password_verify($senha, $usuario['senha_hash'])) {
                    $_SESSION['usuario_id'] = $usuario['id'];
                    $_SESSION['usuario_nome'] = $usuario['nome'];
                    
                    $stmt = $pdo->prepare("UPDATE usuarios SET ultimo_acesso = NOW() WHERE id = ?");
                    $stmt->execute([$usuario['id']]);
                    
                    header("Location: index.php");
                    exit;
                } else {
                    $erro = "🔮 As credenciais estão incorretas! Verifique e-mail e senha.";
                }
            } catch(PDOException $e) {
                $erro = "🐉 Erro no sistema! Por favor, tente novamente mais tarde.";
                error_log("Database error: " . $e->getMessage());
            }
        } else {
            $erro = "🧙‍♂️ A verificação reCAPTCHA falhou! Tente novamente.";
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .login-container {
            max-width: 500px;
            margin: 0 auto;
            padding: 2rem;
            background: white;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .recaptcha-container {
            margin: 1.5rem 0;
            padding: 1rem;
            background: #f8f9fa;
            border-radius: 5px;
        }
        .btn-magic {
            background-color: #6f42c1;
            border: none;
            padding: 10px 20px;
            font-size: 1.1rem;
            transition: all 0.3s;
        }
        .btn-magic:hover {
            background-color: #5a32a3;
            transform: translateY(-2px);
        }
        .alert {
            border-left: 5px solid #dc3545;
        }
        .text-muted {
            color: #6c757d;
        }
        .form-label {
            font-weight: 500;
        }
    </style>
</head>
<body class="d-flex justify-content-center align-items-center min-vh-100">
    <div class="login-container">
        <div class="text-center mb-4">
            <img src="https://via.placeholder.com/100" alt="Logo" class="mb-3">
            <h2>Portal do Aventureiro</h2>
            <p class="text-muted">Entre em seu reino</p>
        </div>
        
        <?php if ($erro): ?>
            <div class="alert alert-danger alert-dismissible fade show">
                <?= $erro ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>
        
        <form method="POST">
            <div class="mb-3">
                <label for="email" class="form-label">📧 Email</label>
                <input type="email" class="form-control" id="email" name="email" required>
            </div>
            
            <div class="mb-3">
                <label for="senha" class="form-label">🔒 Senha</label>
                <input type="password" class="form-control" id="senha" name="senha" required>
            </div>
            
            <div class="recaptcha-container text-center">
                <div class="g-recaptcha" data-sitekey="6Le2ueYqAAAAAK6blZSmXot6VOHqYU689flSfR5w"></div>
            </div>
            
            <div class="d-grid gap-2">
                <button type="submit" class="btn btn-magic text-white">
                    ✨ Lançar Feitiço de Acesso
                </button>
            </div>
        </form>
        
        <div class="text-center mt-3">
            <a href="#" class="text-decoration-none">Esqueceu sua senha?</a>
        </div>
    </div>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>