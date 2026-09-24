using Microsoft.AspNetCore.Http;

namespace Dreamine.Identity.Internal;

internal static class IdentityLocalization
{
    internal sealed record LanguageOption(string Code, string Flag, string NativeName);

    internal sealed record ConsentCopy(
        string RequiredConsents,
        string RequiredPrefix,
        string TermsAgreement,
        string PrivacyAgreement,
        string MinimumAgeConfirmation,
        string MinimumAgeNotice,
        string ConsentRequiredMessage,
        string SignupNotice,
        string LegalNotice);

    internal sealed record Copy(
        string HtmlLanguage, string Login, string Signup, string LoginLead, string Name, string Email,
        string Password, string SocialHint, string ConfirmPassword, string HasAccount, string NoAccount,
        string Or, string GoogleGuide, string EmbeddedWarning, string OpenBrowser, string OpenChrome,
        string OpenSamsung, string Account, string AccountLead, string LoginMethod, string DisplayName,
        string Save, string Back, string Logout, string ChangePassword, string CurrentPassword,
        string NewPassword, string ConfirmNewPassword, string PasswordTitle, string ExternalPassword,
        string NotProvided);

    internal static IReadOnlyList<LanguageOption> Languages { get; } =
    [
        new("en", "US", "English"),
        new("es", "ES", "Español"),
        new("fr", "FR", "Français"),
        new("it", "IT", "Italiano"),
        new("pt", "PT", "Português"),
        new("ko", "KR", "한국어"),
        new("ja", "JP", "日本語"),
        new("zh-hans", "CN", "简体中文"),
        new("zh-hant", "HK", "繁體中文"),
        new("vi", "VN", "Tiếng Việt")
    ];

    private static readonly IReadOnlyDictionary<string, ConsentCopy> ConsentCopies =
        new Dictionary<string, ConsentCopy>(StringComparer.OrdinalIgnoreCase)
        {
            ["ko"] = new("필수 동의", "필수", "이용약관 동의", "개인정보 수집·이용 동의", "만 14세 이상입니다.", "만 14세 미만은 법정대리인 동의 확인 절차가 필요하여 현재 직접 가입할 수 없습니다.", "필수 약관 동의와 만 14세 이상 확인을 완료해 주세요.", "처음 이용하시나요? 회원가입 탭에서 필수 동의를 완료해 주세요.", "계정 생성 시 이용약관·개인정보처리방침 동의와 만 14세 이상 확인이 필요합니다."),
            ["en"] = new("Required consents", "Required", "Agree to the Terms of Service", "Agree to the collection and use of personal data", "I am at least 14 years old.", "Users under 14 cannot register directly because verified consent from a legal guardian is required.", "Please complete the required consents and age confirmation.", "New here? Open the Create account tab and complete the required consents.", "Creating an account requires agreement to the Terms and Privacy Policy and confirmation that you are at least 14."),
            ["es"] = new("Consentimientos obligatorios", "Obligatorio", "Aceptar los Términos del servicio", "Aceptar la recopilación y el uso de datos personales", "Tengo al menos 14 años.", "Los menores de 14 años no pueden registrarse directamente porque se requiere el consentimiento verificado de un tutor legal.", "Completa los consentimientos obligatorios y la confirmación de edad.", "¿Es tu primera vez? Abre la pestaña Crear cuenta y completa los consentimientos obligatorios.", "Para crear una cuenta debes aceptar los Términos y la Política de privacidad y confirmar que tienes al menos 14 años."),
            ["fr"] = new("Consentements obligatoires", "Obligatoire", "Accepter les Conditions d’utilisation", "Accepter la collecte et l’utilisation des données personnelles", "J’ai au moins 14 ans.", "Les moins de 14 ans ne peuvent pas s’inscrire directement, car le consentement vérifié d’un représentant légal est requis.", "Veuillez compléter les consentements obligatoires et la confirmation d’âge.", "Première visite ? Ouvrez l’onglet Créer un compte et complétez les consentements obligatoires.", "La création d’un compte exige l’acceptation des Conditions et de la Politique de confidentialité ainsi que la confirmation d’avoir au moins 14 ans."),
            ["it"] = new("Consensi obbligatori", "Obbligatorio", "Accetta i Termini di servizio", "Accetta la raccolta e l’uso dei dati personali", "Ho almeno 14 anni.", "I minori di 14 anni non possono registrarsi direttamente perché è richiesto il consenso verificato di un tutore legale.", "Completa i consensi obbligatori e la conferma dell’età.", "È la prima volta? Apri la scheda Crea account e completa i consensi obbligatori.", "Per creare un account devi accettare i Termini e l’Informativa sulla privacy e confermare di avere almeno 14 anni."),
            ["pt"] = new("Consentimentos obrigatórios", "Obrigatório", "Aceitar os Termos de Serviço", "Aceitar a coleta e o uso de dados pessoais", "Tenho pelo menos 14 anos.", "Menores de 14 anos não podem se cadastrar diretamente porque é necessário o consentimento verificado de um responsável legal.", "Conclua os consentimentos obrigatórios e a confirmação de idade.", "Primeira vez? Abra a aba Criar conta e conclua os consentimentos obrigatórios.", "A criação de uma conta exige a aceitação dos Termos e da Política de Privacidade e a confirmação de que você tem pelo menos 14 anos."),
            ["ja"] = new("必須同意", "必須", "利用規約に同意する", "個人情報の収集・利用に同意する", "14歳以上です。", "14歳未満の方は法定代理人の確認済み同意が必要なため、現在は直接登録できません。", "必須同意と年齢確認を完了してください。", "初めてですか？「アカウント作成」タブで必須同意を完了してください。", "アカウント作成には、利用規約・プライバシーポリシーへの同意と14歳以上であることの確認が必要です。"),
            ["zh-hans"] = new("必要同意", "必选", "同意服务条款", "同意收集和使用个人信息", "我已年满14周岁。", "未满14周岁的用户需要经核实的法定监护人同意，因此目前无法直接注册。", "请完成必要同意和年龄确认。", "首次使用？请打开“创建账户”选项卡并完成必要同意。", "创建账户需要同意服务条款和隐私政策，并确认已年满14周岁。"),
            ["zh-hant"] = new("必要同意", "必選", "同意服務條款", "同意蒐集與使用個人資料", "我已年滿14歲。", "未滿14歲的使用者需要經核實的法定監護人同意，因此目前無法直接註冊。", "請完成必要同意與年齡確認。", "首次使用？請開啟「建立帳戶」分頁並完成必要同意。", "建立帳戶需要同意服務條款與隱私權政策，並確認已年滿14歲。"),
            ["vi"] = new("Đồng ý bắt buộc", "Bắt buộc", "Đồng ý Điều khoản dịch vụ", "Đồng ý việc thu thập và sử dụng dữ liệu cá nhân", "Tôi từ đủ 14 tuổi.", "Người dưới 14 tuổi chưa thể đăng ký trực tiếp vì cần có sự đồng ý đã xác minh của người giám hộ hợp pháp.", "Vui lòng hoàn tất các mục đồng ý bắt buộc và xác nhận độ tuổi.", "Lần đầu sử dụng? Hãy mở thẻ Tạo tài khoản và hoàn tất các mục đồng ý bắt buộc.", "Để tạo tài khoản, bạn phải đồng ý với Điều khoản, Chính sách quyền riêng tư và xác nhận từ đủ 14 tuổi.")
        };

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

    internal static ConsentCopy Consent(Copy copy) => ConsentCopies[LanguageKey(copy)];

    internal static ConsentCopy Consent(string? language) => ConsentCopies[NormalizeLanguage(language)];

    internal static string LanguageKey(Copy copy) => Normalize(copy.HtmlLanguage);

    internal static string NormalizeLanguage(string? language)
    {
        var normalized = Normalize(language);
        return Copies.ContainsKey(normalized) ? normalized : "ko";
    }

    internal static Copy Resolve(HttpContext http)
    {
        var language = http.Request.Query["lang"].ToString();
        if (string.IsNullOrWhiteSpace(language))
        {
            language = http.Request.Cookies["dreamine-language"];
        }

        if (string.IsNullOrWhiteSpace(language))
        {
            language = http.Request.GetTypedHeaders().AcceptLanguage?
                .OrderByDescending(item => item.Quality ?? 1)
                .Select(item => item.Value.Value)
                .FirstOrDefault();
        }

        language = Normalize(language);
        return Copies.TryGetValue(language, out var copy) ? copy : Copies["ko"];
    }

    private static string Normalize(string? language)
    {
        var normalized = language?.Trim().ToLowerInvariant().Replace('_', '-') ?? string.Empty;
        return normalized switch
        {
            "zh" or "zh-cn" or "zh-sg" => "zh-hans",
            "zh-tw" or "zh-hk" or "zh-mo" => "zh-hant",
            _ when normalized.StartsWith("en-", StringComparison.Ordinal) => "en",
            _ when normalized.StartsWith("es-", StringComparison.Ordinal) => "es",
            _ when normalized.StartsWith("fr-", StringComparison.Ordinal) => "fr",
            _ when normalized.StartsWith("it-", StringComparison.Ordinal) => "it",
            _ when normalized.StartsWith("pt-", StringComparison.Ordinal) => "pt",
            _ when normalized.StartsWith("ko-", StringComparison.Ordinal) => "ko",
            _ when normalized.StartsWith("ja-", StringComparison.Ordinal) => "ja",
            _ when normalized.StartsWith("vi-", StringComparison.Ordinal) => "vi",
            _ => normalized
        };
    }
}
