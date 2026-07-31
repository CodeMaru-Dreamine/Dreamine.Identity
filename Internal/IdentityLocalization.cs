using Microsoft.AspNetCore.Http;

namespace Dreamine.Identity.Internal;

internal static class IdentityLocalization
{
    internal sealed record Copy(
        string HtmlLanguage, string Login, string Signup, string LoginLead, string Name, string Email,
        string Password, string SocialHint, string ConfirmPassword, string HasAccount, string NoAccount,
        string Or, string GoogleGuide, string EmbeddedWarning, string OpenBrowser, string OpenChrome,
        string OpenSamsung, string Account, string AccountLead, string LoginMethod, string DisplayName,
        string Save, string Back, string Logout, string ChangePassword, string CurrentPassword,
        string NewPassword, string ConfirmNewPassword, string PasswordTitle, string ExternalPassword,
        string NotProvided);

    private static readonly IReadOnlyDictionary<string, Copy> Copies = new Dictionary<string, Copy>(StringComparer.OrdinalIgnoreCase)
    {
        ["ko"] = new("ko", "로그인", "회원가입", "하나의 계정으로 CodeMaru 및 Dreamine 계열 서비스를 이용합니다.", "이름", "이메일", "비밀번호", "Google, Naver, Kakao로 가입한 계정은 아래 소셜 로그인 버튼을 사용하세요.", "비밀번호 확인", "이미 계정이 있으신가요? 로그인", "계정이 없으신가요? 회원가입", "또는", "Google 로그인 안내", "앱 내부 브라우저에서는 Google 로그인이 차단될 수 있습니다. 브라우저로 연 뒤 다시 시도해 주세요.", "브라우저로 열기", "Chrome으로 열기", "삼성인터넷으로 열기", "내 계정", "CodeMaru 및 Dreamine 계열 서비스에서 사용할 기본 정보를 관리합니다.", "로그인 방식", "표시 이름", "저장", "돌아가기", "로그아웃", "비밀번호 변경", "현재 비밀번호", "새 비밀번호", "새 비밀번호 확인", "비밀번호", "{0} 로그인 계정은 CodeMaru에 별도 비밀번호가 없습니다. 비밀번호 변경은 해당 로그인 제공자에서 진행해 주세요.", "제공되지 않음"),
        ["en"] = new("en", "Sign in", "Create account", "Use one account across CodeMaru and Dreamine services.", "Name", "Email", "Password", "Use the social buttons below for accounts created with Google, Naver, or Kakao.", "Confirm password", "Already have an account? Sign in", "No account yet? Create one", "or", "Google sign-in notice", "Google sign-in may be blocked inside an in-app browser. Open this page in your browser and try again.", "Open in browser", "Open in Chrome", "Open in Samsung Internet", "My account", "Manage the basic information used across CodeMaru and Dreamine services.", "Sign-in method", "Display name", "Save", "Go back", "Sign out", "Change password", "Current password", "New password", "Confirm new password", "Password", "{0} accounts do not have a separate CodeMaru password. Change it with that sign-in provider.", "Not provided"),
        ["es"] = new("es", "Iniciar sesión", "Crear cuenta", "Usa una cuenta en los servicios CodeMaru y Dreamine.", "Nombre", "Correo", "Contraseña", "Usa los botones sociales para cuentas de Google, Naver o Kakao.", "Confirmar contraseña", "¿Ya tienes cuenta? Inicia sesión", "¿No tienes cuenta? Créala", "o", "Aviso de Google", "Google puede bloquearse dentro de un navegador integrado. Abre la página en tu navegador.", "Abrir en navegador", "Abrir en Chrome", "Abrir en Samsung Internet", "Mi cuenta", "Administra la información usada en CodeMaru y Dreamine.", "Método de acceso", "Nombre visible", "Guardar", "Volver", "Cerrar sesión", "Cambiar contraseña", "Contraseña actual", "Nueva contraseña", "Confirmar nueva contraseña", "Contraseña", "Las cuentas de {0} no tienen contraseña separada de CodeMaru. Cámbiala con ese proveedor.", "No disponible"),
        ["fr"] = new("fr", "Connexion", "Créer un compte", "Utilisez un seul compte pour les services CodeMaru et Dreamine.", "Nom", "E-mail", "Mot de passe", "Utilisez les boutons sociaux pour les comptes Google, Naver ou Kakao.", "Confirmer le mot de passe", "Déjà un compte ? Se connecter", "Pas encore de compte ? S’inscrire", "ou", "Information Google", "Google peut être bloqué dans un navigateur intégré. Ouvrez cette page dans votre navigateur.", "Ouvrir dans le navigateur", "Ouvrir dans Chrome", "Ouvrir dans Samsung Internet", "Mon compte", "Gérez les informations utilisées dans CodeMaru et Dreamine.", "Mode de connexion", "Nom affiché", "Enregistrer", "Retour", "Déconnexion", "Modifier le mot de passe", "Mot de passe actuel", "Nouveau mot de passe", "Confirmer le nouveau mot de passe", "Mot de passe", "Les comptes {0} n’ont pas de mot de passe CodeMaru distinct. Modifiez-le auprès du fournisseur.", "Non fourni"),
        ["it"] = new("it", "Accedi", "Crea account", "Usa un solo account per i servizi CodeMaru e Dreamine.", "Nome", "Email", "Password", "Usa i pulsanti social per gli account Google, Naver o Kakao.", "Conferma password", "Hai già un account? Accedi", "Non hai un account? Crealo", "oppure", "Avviso Google", "Google può essere bloccato nel browser interno. Apri la pagina nel browser e riprova.", "Apri nel browser", "Apri in Chrome", "Apri in Samsung Internet", "Il mio account", "Gestisci le informazioni usate nei servizi CodeMaru e Dreamine.", "Metodo di accesso", "Nome visualizzato", "Salva", "Indietro", "Esci", "Cambia password", "Password attuale", "Nuova password", "Conferma nuova password", "Password", "Gli account {0} non hanno una password CodeMaru separata. Modificala presso il provider.", "Non fornita"),
        ["pt"] = new("pt", "Entrar", "Criar conta", "Use uma conta nos serviços CodeMaru e Dreamine.", "Nome", "Email", "Senha", "Use os botões sociais para contas Google, Naver ou Kakao.", "Confirmar senha", "Já tem conta? Entre", "Não tem conta? Crie uma", "ou", "Aviso do Google", "O Google pode ser bloqueado no navegador interno. Abra a página no navegador.", "Abrir no navegador", "Abrir no Chrome", "Abrir no Samsung Internet", "Minha conta", "Gerencie as informações usadas no CodeMaru e Dreamine.", "Método de login", "Nome de exibição", "Salvar", "Voltar", "Sair", "Alterar senha", "Senha atual", "Nova senha", "Confirmar nova senha", "Senha", "Contas {0} não têm senha separada no CodeMaru. Altere-a no provedor.", "Não informado"),
        ["vi"] = new("vi", "Đăng nhập", "Tạo tài khoản", "Dùng một tài khoản cho các dịch vụ CodeMaru và Dreamine.", "Tên", "Email", "Mật khẩu", "Dùng nút đăng nhập mạng xã hội cho tài khoản Google, Naver hoặc Kakao.", "Xác nhận mật khẩu", "Đã có tài khoản? Đăng nhập", "Chưa có tài khoản? Tạo ngay", "hoặc", "Lưu ý đăng nhập Google", "Google có thể bị chặn trong trình duyệt trong ứng dụng. Hãy mở bằng trình duyệt.", "Mở trong trình duyệt", "Mở bằng Chrome", "Mở bằng Samsung Internet", "Tài khoản của tôi", "Quản lý thông tin dùng trong CodeMaru và Dreamine.", "Phương thức đăng nhập", "Tên hiển thị", "Lưu", "Quay lại", "Đăng xuất", "Đổi mật khẩu", "Mật khẩu hiện tại", "Mật khẩu mới", "Xác nhận mật khẩu mới", "Mật khẩu", "Tài khoản {0} không có mật khẩu CodeMaru riêng. Hãy đổi tại nhà cung cấp.", "Chưa cung cấp"),
        ["ja"] = new("ja", "ログイン", "アカウント作成", "CodeMaru と Dreamine のサービスを1つのアカウントで利用できます。", "名前", "メール", "パスワード", "Google、Naver、Kakaoで作成したアカウントは下のソーシャルボタンを使用してください。", "パスワード確認", "アカウントをお持ちですか？ログイン", "アカウントがありませんか？作成", "または", "Googleログインのお知らせ", "アプリ内ブラウザではGoogleログインがブロックされる場合があります。ブラウザで開いてください。", "ブラウザで開く", "Chromeで開く", "Samsung Internetで開く", "マイアカウント", "CodeMaru と Dreamine で使用する基本情報を管理します。", "ログイン方法", "表示名", "保存", "戻る", "ログアウト", "パスワード変更", "現在のパスワード", "新しいパスワード", "新しいパスワードの確認", "パスワード", "{0}アカウントにはCodeMaru専用パスワードがありません。提供元で変更してください。", "未提供"),
        ["zh-hans"] = new("zh-Hans", "登录", "创建账户", "使用一个账户访问 CodeMaru 和 Dreamine 服务。", "姓名", "电子邮件", "密码", "Google、Naver 或 Kakao 账户请使用下方社交登录按钮。", "确认密码", "已有账户？登录", "还没有账户？创建", "或", "Google 登录提示", "应用内浏览器可能会阻止 Google 登录，请在浏览器中打开。", "在浏览器中打开", "使用 Chrome 打开", "使用三星浏览器打开", "我的账户", "管理 CodeMaru 和 Dreamine 服务使用的基本信息。", "登录方式", "显示名称", "保存", "返回", "退出登录", "修改密码", "当前密码", "新密码", "确认新密码", "密码", "{0} 账户没有单独的 CodeMaru 密码，请在登录提供商处修改。", "未提供"),
        ["zh-hant"] = new("zh-Hant", "登入", "建立帳戶", "使用一個帳戶存取 CodeMaru 與 Dreamine 服務。", "姓名", "電子郵件", "密碼", "Google、Naver 或 Kakao 帳戶請使用下方社群登入按鈕。", "確認密碼", "已有帳戶？登入", "還沒有帳戶？建立", "或", "Google 登入提示", "應用程式內瀏覽器可能會阻擋 Google 登入，請在瀏覽器中開啟。", "在瀏覽器中開啟", "使用 Chrome 開啟", "使用 Samsung Internet 開啟", "我的帳戶", "管理 CodeMaru 與 Dreamine 服務使用的基本資料。", "登入方式", "顯示名稱", "儲存", "返回", "登出", "變更密碼", "目前密碼", "新密碼", "確認新密碼", "密碼", "{0} 帳戶沒有獨立的 CodeMaru 密碼，請在登入提供者處變更。", "未提供")
    };

    internal static Copy Default => Copies["ko"];

    internal static Copy Resolve(HttpContext http)
    {
        var language = http.Request.Query["lang"].ToString();
        if (string.IsNullOrWhiteSpace(language))
        {
            language = http.Request.Cookies["dreamine-language"];
        }

        language = language?.Trim().ToLowerInvariant().Replace('_', '-');
        return language is not null && Copies.TryGetValue(language, out var copy) ? copy : Copies["ko"];
    }
}
