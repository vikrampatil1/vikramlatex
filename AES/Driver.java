/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package AES;

/**
 *
 * @author ek10
 */
import java.util.Scanner;

public class Driver {
    public static void main(String args[]){    
           
             //Takes input from user and stores in inputkey
    Scanner in1 = new Scanner(System.in);
    String inputKey = in1.nextLine();
    
    //Takes 2nd input from user and stores in inputPlainText
    Scanner in2 = new Scanner(System.in);
    String plainText = in2.nextLine();
    //If condition makes sure that user has entered exactly 32 hexadecimal digits
    if(!inputKey.isEmpty() || !plainText.isEmpty()){
    if ( (inputKey.matches("[0-9A-F]{32}") ) && (plainText.matches("[0-9A-F]{32}"))) {      
      //cText stores the ciphertext
      AEScipher kg = new AEScipher();
      String cText = kg.aes(plainText, inputKey);
      
      //Print the ciphertext
      System.out.print(cText);
    }
      else {
      //If user input is incorrect, terminate the program
      System.out.println("Invalid input key or plaintext, exiting.....");
    }
    }
    else{System.out.println("Problem in input");}
             
    }
    
}
