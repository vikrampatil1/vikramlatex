/**
* file: Driver.java
* author: Vikram Patil
* course: Security Algorithms and Protocols
* assignment: Lab 3
* due date: April 1 2016
* version: 1.2
*/


import java.util.Scanner;

public class Driver {
    public static void main(String args[]){           
    //Taking Command line inputs as Plaintext and Key         
    Scanner in1 = new Scanner(System.in);
    String inputKey = in1.nextLine();    
    Scanner in2 = new Scanner(System.in);
    String plainText = in2.nextLine();
    //Checking the input strings are in hexadecimal format and are of lenghth 32
    if(!inputKey.isEmpty() || !plainText.isEmpty()){
    if ( (inputKey.matches("[0-9A-F]{32}") ) && (plainText.matches("[0-9A-F]{32}"))) {     
      AEScipher kg = new AEScipher();
      String cText = kg.aes(plainText, inputKey);
      System.out.print(cText);
    }
    else {      
      System.out.println("Wrong Input");
    }
    }
    else{System.out.println("Please give correct input");}
             
    }    
}
