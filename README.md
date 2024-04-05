# basicwebsiteanalyzer

TR: Bu kod, bir Tkinter GUI (grafiksel kullanıcı arayüzü) kullanarak bir web sitesinin güvenlik analizini yapar ve çeşitli güvenlik özelliklerini kontrol eder. Aşağıda kodun ne yaptığını detaylı olarak yer verdim:

Modüllerin İçe Aktarılması: Tkinter, messagebox, scrolledtext, urlparse, requests, BeautifulSoup, ssl, re, socket ve pyperclip gibi gerekli modüller içe aktarılır. Bu modüller, kullanıcı arayüzü oluşturmak, web sayfalarını almak ve analiz etmek için gereklidir.

Fonksiyonlar: Kod, panoya metin kopyalama, hata mesajı gösterme ve güvenlik analizi yapma gibi çeşitli fonksiyonları içerir. Bu fonksiyonlar, işlevsel ayrıntılar sağlar ve kodun daha modüler olmasını sağlar.

Güvenlik Analizi Fonksiyonu (analyze_security): Bu fonksiyon, kullanıcının girdiği bir URL'yi alır ve şu güvenlik unsurlarını kontrol eder:

SSL/TLS sertifikasının varlığı
Güvenlik başlıklarının varlığı
Güvensiz bağlantıları tespit etme (HTTPS kullanılmayan bağlantılar)
Karışık içeriği kontrol etme
IP adresini ve port numarasını alma
HTTP Strict Transport Security (HSTS) başlığının varlığı
Ekstra Özellikler:

Potansiyel XSS ve SQL Enjeksiyonu tespiti: Web sayfasının içeriğinde <script> veya "SQL syntax error" ifadelerinin bulunması durumunda kullanıcıya uyarı mesajı gösterilir.
Çerezleri gösterme: Web sitesinden alınan çerezler kullanıcıya gösterilir.
Yanıt başlıklarını gösterme: Web sunucusundan alınan yanıt başlıkları kullanıcıya gösterilir.
Tarayıcı geliştirici araçlarını açma: Kullanıcıya tarayıcı geliştirici araçlarını açması için bir bilgi iletişim kutusu gösterilir.
URL'de belirli bir anahtar kelime varsa ters kabuk açma: URL'de "exploit" kelimesi bulunursa, bir ters kabuk açma işlemi gerçekleştirilir. (Bu bir güvenlik açığıdır ve gerçek uygulamalarda asla kullanılmamalıdır.)
Hata Yönetimi: İşlem sırasında olası hataların yönetimi sağlanır. Örneğin, URL çözümlenemezse veya web sitesine erişimde bir hata oluşursa, kullanıcıya uygun hata mesajları gösterilir.

Tkinter Arayüzü Oluşturma: Tkinter kullanılarak basit bir grafiksel kullanıcı arayüzü oluşturulur. Kullanıcıdan bir URL girmesi istenir ve "Analyze" düğmesine tıkladığında, analyze_security fonksiyonu çağrılır ve sonuçlar analiz alanında görüntülenir.

Bu kodun temel amacı, bir web sitesinin güvenlik durumunu hızlı bir şekilde analiz etmek ve kullanıcıya analiz sonuçlarını sunmaktır. Ancak, dikkat edilmesi gereken bazı noktalar şunlardır:

Bazı ekstra özellikler, gerçek dünyada etik olmayan veya tehlikeli olabilecek uygulamalara açık kapılar bırakabilir. Özellikle, ters kabuk açma işlemi gibi potansiyel güvenlik açıkları dikkatlice ele alınmalı ve yalnızca güvenli test ortamlarında kullanılmalıdır.
Bu kod, yalnızca basit güvenlik kontrolleri yapar. Gerçek bir güvenlik analizi için daha kapsamlı araçlar ve deneyimli bir uzmana ihtiyaç duyulur.


EN: This code performs a security analysis of a website using a Tkinter GUI (Graphical User Interface) and checks various security features. Below is a detailed description of what the code does:

Importing Modules: Necessary modules like Tkinter, messagebox, scrolledtext, urlparse, requests, BeautifulSoup, ssl, re, socket, and pyperclip are imported. These modules are required for creating the user interface, fetching web pages, and performing analysis.

Functions: The code includes various functions such as copying text to the clipboard, displaying error messages, and performing security analysis. These functions provide functional details and make the code more modular.

Security Analysis Function (analyze_security): This function takes a URL entered by the user and checks the following security aspects:

Presence of SSL/TLS certificate
Presence of security headers
Detection of insecure connections (links not using HTTPS)
Checking for mixed content
Retrieving IP address and port number
Presence of HTTP Strict Transport Security (HSTS) header
Extra Features:

Potential XSS and SQL Injection detection: If <script> or "SQL syntax error" expressions are found in the web page content, a warning message is displayed to the user.
Displaying cookies: Cookies obtained from the website are shown to the user.
Showing response headers: Response headers obtained from the web server are displayed to the user.
Opening developer tools in the browser: A message box is shown to the user to open browser developer tools.
Opening a reverse shell if a specific keyword is found in the URL: If the word "exploit" is found in the URL, a reverse shell operation is performed. (This is a security vulnerability and should never be used in real applications.)
Error Handling: Management of possible errors during the process is ensured. For example, if a URL cannot be resolved or if there is an error accessing the website, appropriate error messages are shown to the user.

Creating Tkinter Interface: A simple graphical user interface is created using Tkinter. The user is prompted to enter a URL, and when they click the "Analyze" button, the analyze_security function is called, and the results are displayed in the analysis area.

The main purpose of this code is to quickly analyze the security status of a website and present the analysis results to the user. However, some points to note are:

Some extra features may open doors to unethical or potentially dangerous practices in the real world. Especially, potential security vulnerabilities like the reverse shell operation should be handled carefully and should only be used in secure testing environments.
This code performs only basic security checks. For a real security analysis, more comprehensive tools and an experienced professional are required.
