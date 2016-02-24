
import java.math.BigInteger;


/**
 * Author : Vikram Patil
 * Date : 23 Feb 2016
 * Description: Security Algorithm assignment
 */
public class AESKeyGenerator {
    
    private static String[][] originalKey = new String[4][4];
    public static String[][] W = new String[4][44];
    
    private static final String[][] SBOX = {
		{ "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76" },
		{ "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0" },
		{ "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15" },
		{ "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75" },
		{ "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84" },
		{ "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF" },
		{ "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8" },
		{ "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2" },
		{ "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73" },
		{ "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB" },
		{ "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79" },
		{ "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08" },
		{ "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A" },
		{ "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E" },
		{ "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF" },
		{ "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16" } };

	private static final String[][] RCON = {
		{ "8D", "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36", "6C", "D8", "AB", "4D", "9A" },
		{ "2F", "5E", "BC", "63", "C6", "97", "35", "6A", "D4", "B3", "7D", "FA", "EF", "C5", "91", "39" },
		{ "72", "E4", "D3", "BD", "61", "C2", "9F", "25", "4A", "94", "33", "66", "CC", "83", "1D", "3A" },
		{ "74", "E8", "CB", "8D", "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36", "6C", "D8" },
		{ "AB", "4D", "9A", "2F", "5E", "BC", "63", "C6", "97", "35", "6A", "D4", "B3", "7D", "FA", "EF" },
		{ "C5", "91", "39", "72", "E4", "D3", "BD", "61", "C2", "9F", "25", "4A", "94", "33", "66", "CC" },
		{ "83", "1D", "3A", "74", "E8", "CB", "8D", "01", "02", "04", "08", "10", "20", "40", "80", "1B" },
		{ "36", "6C", "D8", "AB", "4D", "9A", "2F", "5E", "BC", "63", "C6", "97", "35", "6A", "D4", "B3" },
		{ "7D", "FA", "EF", "C5", "91", "39", "72", "E4", "D3", "BD", "61", "C2", "9F", "25", "4A", "94" },
		{ "33", "66", "CC", "83", "1D", "3A", "74", "E8", "CB", "8D", "01", "02", "04", "08", "10", "20" },
		{ "40", "80", "1B", "36", "6C", "D8", "AB", "4D", "9A", "2F", "5E", "BC", "63", "C6", "97", "35" },
		{ "6A", "D4", "B3", "7D", "FA", "EF", "C5", "91", "39", "72", "E4", "D3", "BD", "61", "C2", "9F" },
		{ "25", "4A", "94", "33", "66", "CC", "83", "1D", "3A", "74", "E8", "CB", "8D", "01", "02", "04" },
		{ "08", "10", "20", "40", "80", "1B", "36", "6C", "D8", "AB", "4D", "9A", "2F", "5E", "BC", "63" },
		{ "C6", "97", "35", "6A", "D4", "B3", "7D", "FA", "EF", "C5", "91", "39", "72", "E4", "D3", "BD" },
		{ "61", "C2", "9F", "25", "4A", "94", "33", "66", "CC", "83", "1D", "3A", "74", "E8", "CB", "8D" } };
    
        
        public static void generateRoundKeys(String input){
           
            //Taking input as Master key and storing in a 4x4 matrix
            int i =0;
		for (int col1 = 0; col1 <=3; col1++) {			
                    for (int row1 = 0; row1 <=3; row1 = row1+1) {
			originalKey[row1][col1] = input.substring(i,i+2);
			i=i+2;
                    }               
		}           
            //take the original key and make it be the first four columns of W
            for(int row2 = 0; row2<=3; row2++){
                for(int col2 = 0; col2 < 4; col2++){
                    W[row2][col2] = originalKey[row2][col2];
                }
            }   
            //Starting to create next 40 columns of W
            //temporary matrix temp_w for processing
            String[][] temp_w = null;
            for(int column = 4; column<=43; column++){
            /*Part 1 : if the index of column is not divisible by 4, 
            XOR the fourth past and last column with respect to column index*/
                if(column % 4 != 0){
                    for(int row = 0; row<=3; row++){
                        W[row][column] = performXOR(W[row][column-4], W[row][column-1]); 
                    }
                }
                else {
            /*Part 2 : if the index of column is divisible by 4,
              step 1: Use temp matrix temp_w to store previous column values.
                      Tanspose previous column values to row values
              step 2 : Shif to the left of column values of temp_w*/
                    temp_w = new String[1][4];       
              
                    temp_w[0][0] = W[1][column - 1];
                    temp_w[0][1] = W[2][column - 1];
                    temp_w[0][2] = W[3][column - 1];
                    temp_w[0][3] = W[0][column - 1];
                    
              //step 3 : transform each of the four bytes in temp_w using an S-box function
                    for(int m =0 ; m<1; m++){
                        for(int n =0; n<=3 ; n++){
                            int x = Integer.parseInt(temp_w[m][n].split("")[0],16);
                            int y = Integer.parseInt(temp_w[m][n].split("")[1],16);
                            temp_w[m][n] = SBOX[x][y];                                              
			}
                    }
              
              //step 4 : Getting RCon coefficient values and performing XOR operation
                    //find number of round
                    int numRound = column/4;
                    //get RCon of the same column number form Rcon table and xOR with first element
                    temp_w[0][0] = performXOR(RCON[0][numRound],temp_w[0][0]);
                    
              //step 5 : Perform final XOR
                    for(int row3 = 0; row3<=3; row3++){
                        W[row3][column] = performXOR(W[row3][column-4], temp_w[0][row3]);
                    }
                    
            }
            }
                
                //Printing Round Keys
                int Rounds = 1;
                int k = 0;
                while (Rounds <=11){                
                    for(int column1 = 0; column1<=3; k++, column1++){
                        for(int row =0; row<=3; row++){
                        System.out.print(W[row][k]);
                        }
                    }                
                System.out.println();
                Rounds++;
                }           
                System.out.println("");
            }
        
               
        public static String performXOR(String one, String two){
            BigInteger val1 = new BigInteger(one, 16);
            BigInteger val2 = new BigInteger(two, 16);
            BigInteger res = val1.xor(val2);
            String result = res.toString(16);              
            return result.length() == 1 ? ("0" +result.toUpperCase()): result.toUpperCase();
        }
        
}
