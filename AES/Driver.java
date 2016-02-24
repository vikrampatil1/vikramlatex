 /* Author : Vikram Patil
 * Date : 23 Feb 2016
 * Description: Security Algorithm assignment
*/
import java.util.Scanner;

public class Driver {
    public static void main(String args[]){    
           
             Scanner sc = new Scanner(System.in);
	     String input = sc.nextLine();	    
	     AESKeyGenerator kg = new AESKeyGenerator();
	     kg.generateRoundKeys(input);
             
    }
    
}
