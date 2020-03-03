import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class TripleDES {
	
	static String mensagemErro = "";
	
	public TripleDES() {
        super();
    } 
	
    public static void main(String[] args) throws Exception {
        try {
        	limpaErro();
        	
            // Chave de desencriptação
            String decKey = "UqOKIBu82BMiz4hEh+TqJpobsO9DonWo";            
            System.out.println("decKey: "+decKey);
            
            // Chave de encriptação do websevice cadastrado no AnnA
            String encKey = "tfR/F6ZhqVIFQ+2LNWTf+/dAz3urb3sf";
            System.out.println("encKey: "+encKey);
            
            // IV sem encriptação
            String iv = "rhGY1xiNqEL=";
            System.out.println("ivRecebido: "+iv);
       
            String json = "{";
            json += "  \"ClientStatus\":\"OK\",";
            json += "  \"ClientMessage\":\"\",";
            json += "  \"DevCallback\":\"\",";
            json += "  \"Containers\":[";
            json += "      {";
            json += "      \"Type\":\"MSG\",";
            json += "      \"Phrase\":\"O valor de AnotherVar é: \",";
            json += "      \"Alias\":\"AliasAnotherVar\",";
            json += "      \"Subject\":\"\",";
            json += "      \"Topic\":\"\",";
            json += "      \"Scope\":\"\",";
            json += "      \"AnswerType\":\"\",";
            json += "      \"AnswerTypeComment\":\"\",";
            json += "      \"MediaURL\":\"\",";
            json += "      \"ShowMsgHeader\":\"\",";
            json += "      \"WaitNext\":0,";
            json += "      \"Enumeration\":\"\",";
            json += "      \"JumpType\":\"\",";
            json += "      \"JumpTo\":\"\",";
            json += "      \"ResumeType\":\"\",";
            json += "      \"ResumeTo\":\"\",";
            json += "      \"WsEncodeUrl\":\"\"";
            json += "      ,\"WsUrl\":\"\",";
            json += "      \"WsCallBackUrl\":\"\",";
            json += "      \"WsCallBackMsg\":\"\",";
            json += "      \"IgnoreServices\":\"\",";
            json += "      \"ExternalData\":\"\",";
            json += "      \"RespostaDefault\":\"\",";
            json += "      \"GroupAlias\":\"\",";
            json += "      \"IsSensitive\":\"\"";
            json += "      }";
            json += "  ]";
            json += "}";
            System.out.println("json: "+json); 
                       
            String finalResponse = strencrypt(json, encKey, iv);
            System.out.println("finalResponse criptografado: "+finalResponse);
              
            String finalResponse2 = strdecrypt(finalResponse, encKey, iv);
            System.out.println("finalResponse2 decifrado: "+finalResponse2);
              
        } catch (Exception ex) {
        	gravaErro(ex);
        	System.out.println("Erros: " + mensagemErro);
        }
    }
   
    public static String strencrypt(String message, String pkey, String piv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {
    	limpaErro();
    	try {
	    	byte[] ivDecoded = Base64.getDecoder().decode(piv);
	        byte[] keyDecoded = Base64.getDecoder().decode(pkey);
	       
	        IvParameterSpec iv = new IvParameterSpec(ivDecoded);
	        SecretKey key = new SecretKeySpec(keyDecoded, "DESede");
	   
	        String messageCript = encrypt(message, key, iv);
			 
			return messageCript;
    	}catch (Exception ex) {
    		gravaErro(ex);
			return "";
    	}
	 }
    
    public static String strdecrypt(String message, String pkey, String piv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException, IOException {
    	limpaErro();
    	try {
    		byte[] ivDecoded = Base64.getDecoder().decode(piv.getBytes("UTF-8"));
			IvParameterSpec iv = new IvParameterSpec(ivDecoded);
			
	        byte[] KeyDecoded = Base64.getDecoder().decode(pkey.getBytes("UTF-8"));
	        SecretKey key = new SecretKeySpec(KeyDecoded, "DESede");
	
	        String messageDecript = decrypt(message, key, iv);
			
	        return messageDecript;
	    }catch (Exception ex) {
			gravaErro(ex);
			return "";
		}
	}
    
    private static String encrypt(String message, SecretKey key, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {    
        final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);        
        byte[] plainTextBytes = message.getBytes("utf-8");
        byte[] buf = cipher.doFinal(plainTextBytes);
        byte[] base64Bytes = Base64.getEncoder().encode(buf);
        String base64EncryptedString = new String(base64Bytes);        
        return base64EncryptedString;       
    }
    
    private static String decrypt(String encMessage, SecretKey key, IvParameterSpec iv) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] message = Base64.getDecoder().decode(encMessage.getBytes("utf-8"));      
        final Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        decipher.init(Cipher.DECRYPT_MODE, key, iv);        
        byte[] plainText = decipher.doFinal(message);        
        return new String(plainText, "UTF-8");
    }
     
     public static String strcriaIvDummy() throws Exception{
    	 limpaErro();
    	 try {
    	 	IvParameterSpec iv = criaIvDummy();
	     	byte[] iVByte = iv.getIV();	
	     	String ret = Base64.getEncoder().encodeToString(iVByte);
	     	return ret;
     	}catch (Exception ex) {
			gravaErro(ex);
			return "";
		}
     }
     
     private static IvParameterSpec criaIvDummy() throws Exception{
     	byte[] randomBytes = new byte[8];
         new Random().nextBytes(randomBytes);
         IvParameterSpec iV = new IvParameterSpec(randomBytes);
 		return iV;
     }
     
     private static void gravaErro(Exception e) {
 		mensagemErro = e.getMessage();
 	}
     
     private static void limpaErro() {
 		mensagemErro = "";
 	}
}
