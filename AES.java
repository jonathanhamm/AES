/*
 * AES implementation. 
 * CS 4153: Computer Security
 * Project 1
 * 
 * Authors: Cameron Beckfield and Jonathan Hamm
 */

public class AES {
	private final int Nb = 4;
	private final int WORD = 4;
	private int Nk; 
	private int Nr;
	private byte[] key;
	private byte[][] w;
	private byte[][] state;
	private byte[][] rcon;
	private static byte[] tkey = {0x2b,0x7e,0x15,0x16,0x28,(byte)0xae,(byte)0xd2,(byte)0xa6,(byte)0xab,(byte)0xf7,0x15,(byte)0x88,0x09,(byte)0xcf,0x4f,0x3c};
	private static byte[] tcipher = {0x32,0x43,(byte)0xf6,(byte)0xa8,(byte)0x88,0x5a,0x30,(byte)0x8d,0x31,0x31,(byte)0x98,(byte)0xa2,(byte)0xe0,0x37,0x07,0x34};

	/*Class for Interfacing with the SBox*/
	private static class SBox {
		final private static byte[][] SBOX_= {
			{0x63, 0x7c, 0x77, 0x7b, (byte) 0xf2, 0x6b, 0x6f, (byte) 0xc5, 0x30, 0x01, 0x67, 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, 0x76}, 
			{(byte)0xca, (byte)0x82, (byte) 0xc9, 0x7d, (byte) 0xfa, 0x59, 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte)0xaf, (byte) 0x9c, (byte)0xa4, 0x72, (byte) 0xc0},
			{(byte)0xb7, (byte)0xfd, (byte)0x93, 0x26, 0x36, 0x3f, (byte) 0xf7, (byte)0xcc, 0x34, (byte)0xa5, (byte)0xe5, (byte)0xf1, 0x71, (byte)0xd8, 0x31, 0x15},
			{0x04, (byte)0xc7, 0x23, (byte)0xc3, 0x18, (byte)0x96, 0x05, (byte)0x9a, 0x07, 0x12, (byte)0x80, (byte)0xe2, (byte)0xeb, 0x27,(byte) 0xb2, 0x75},
			{0x09, (byte)0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, (byte)0xa0, 0x52, 0x3b, (byte)0xd6,(byte)0xb3, 0x29, (byte)0xe3, 0x2f, (byte)0x84}, 
			{0x53, (byte)0xd1, 0x00, (byte)0xed, 0x20, (byte)0xfc, (byte)0xb1, 0x5b, 0x6a, (byte)0xcb, (byte)0xbe, 0x39, 0x4a, 0x4c, 0x58, (byte)0xcf}, 
			{(byte)0xd0, (byte)0xef, (byte)0xaa, (byte)0xfb, 0x43, 0x4d, 0x33, (byte)0x85, 0x45, (byte)0xf9, 0x02, 0x7f, 0x50, 0x3c, (byte)0x9f, (byte)0xa8}, 
			{0x51, (byte)0xa3, 0x40, (byte)0x8f, (byte)0x92, (byte)0x9d, 0x38, (byte)0xf5, (byte)0xbc, (byte)0xb6, (byte)0xda, 0x21, 0x10, (byte)0xff, (byte)0xf3, (byte)0xd2},
			{(byte)0xcd, 0x0c, 0x13, (byte)0xec, 0x5f, (byte)0x97, 0x44, 0x17, (byte)0xc4, (byte)0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
			{0x60, (byte)0x81, 0x4f, (byte)0xdc, 0x22, 0x2a, (byte)0x90, (byte)0x88, 0x46, (byte)0xee, (byte)0xb8, 0x14, (byte)0xde, 0x5e, 0x0b, (byte)0xdb},
			{(byte)0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, (byte)0xc2, (byte)0xd3, (byte)0xac, 0x62, (byte)0x91, (byte)0x95, (byte)0xe4, 0x79}, 
			{(byte)0xe7, (byte)0xc8, 0x37, 0x6d, (byte)0x8d, (byte)0xd5, 0x4e, (byte)0xa9, 0x6c, 0x56, (byte)0xf4, (byte)0xea, 0x65, 0x7a, (byte)0xae, 0x08}, 
			{(byte)0xba, 0x78, 0x25, 0x2e, 0x1c, (byte)0xa6, (byte)0xb4, (byte)0xc6, (byte)0xe8, (byte)0xdd, 0x74, 0x1f, 0x4b, (byte)0xbd, (byte)0x8b, (byte)0x8a},
			{0x70, 0x3e, (byte)0xb5, 0x66, 0x48, 0x03, (byte)0xf6, 0x0e, 0x61, 0x35, 0x57, (byte)0xb9, (byte)0x86, (byte)0xc1, 0x1d, (byte)0x9e}, 
			{(byte)0xe1, (byte)0xf8, (byte)0x98, 0x11, 0x69, (byte)0xd9, (byte)0x8e, (byte)0x94, (byte)0x9b, 0x1e, (byte)0x87, (byte)0xe9, (byte)0xce, 0x55, 0x28, (byte)0xdf}, 
			{(byte)0x8c, (byte)0xa1, (byte)0x89, 0x0d, (byte)0xbf, (byte)0xe6, 0x42, 0x68, 0x41, (byte)0x99, 0x2d, 0x0f, (byte)0xb0, 0x54, (byte)0xbb, 0x16} 
		};
		
		/*Performs Substitution on plaintext*/
		public static byte sub (int b) {
			b &= 0x000000ff;
			return SBOX_[b >> 4][b & 0x0f];
		}
		/*Inverts Substitution onf plaintext*/
		public static byte invert (int b) {
			b &= 0x000000ff;
			return SBOX_[b & 0x0f][b >> 4];
		}
	}
	static public byte xtime (byte b) {
		if ((b & (byte)0x80) != 0)
			return (byte)((b << 1) ^ 0x1b);
		return (byte)(b << 1);
	}
	/*Constructor*/
	public AES (byte[] key) {
		/*Build rcon table*/
		rcon = new byte[256][WORD];
		/*
		 * This initial value (0x8d) makes the key schedule table populate with the
		 * correct values. The algorithm description begins at index 1, so 0x8d is
		 * needed at index 0 as a start point. Got value from Wiki. 
		 */
		byte b = (byte)0x8d; 
		for (int i = 0; i < 256; i++) {
			rcon[i][0] = b;
			if ((b & (byte)0x80) == 0)
				b = (byte)(b << 1);
			else 
				b = (byte)((byte)(b << 1) ^ (byte)0x1b);
		}
		/*Set up other constants*/
		switch (key.length) {
			case 16:
				Nk = 4;
                Nr = 10;
				break;
			case 24:
				Nk = 6;
                Nr = 12;
				break;
			case 32:
				Nk = 8;
                Nr = 14;
				break;
			default:
				System.out.println("Invalid Key Length");
				break;
		}
		this.key = key;
		w = new byte[Nb*(Nr+1)][4];
	}
		
	/*Perform Plaintext substitution*/
	private void subBytes () {
		for (int i = 0; i < Nk; i++) {
			for (int j = 0; j < Nb; j++)
				state[i][j] = SBox.sub(state[i][j]);
		}
	}
	
	private static byte multx (byte b, byte x) 
	{
		byte prod = 0, shift = 1, xt;
		
		xt = b;
		do {
			if ((x & shift) != 0)
				prod ^= xt;
			xt = xtime (xt);
			shift <<= 1;
			//System.out.printf("Comparing %d < %d\n",((int)shift & 0x000000ff), ((int)x & 0x0000000ff));
		}
		while (shift != 0 && ((int)shift & 0x000000ff) <= ((int)x & 0x0000000ff));
		return prod;
	}
	
	/* Shift rows - first row not affected */
    private void shiftRows() {
        byte tmp[][] = new byte[Nk][Nb];
    	
		for (int i = 0; i < Nk; i++)
			for (int j = 0; j < Nb; j++)
				tmp[i][j] = this.state[i][j];
		for (int row = 1; row < Nb; row++)
            for (int col = 0; col < Nb; col++)
                this.state[row][col] = tmp[row][(col+row)%Nb];
	}
	
	private void mixColumns() {
		byte tmp[][] = new byte[Nk][Nb];
		/*byte[][] test = {
				{(byte)0xd4,(byte)0xe0,(byte)0xb8,0x1e},
				{(byte)0xbf,(byte)0xb4,0x41,0x27},
				{0x5d,0x52,0x11,(byte)0x98},
				{0x30,(byte)0xae,(byte)0xf1,(byte)0xe5}
		};
		for (int i = 0; i < Nk; i++){
			for (int j = 0; j < Nb; j++)
				this.state[i][j] = test[i][j];
		}*/
		for (int i = 0; i < Nk; i++) {
			for (int j = 0; j < Nb; j++)
				tmp[i][j] = this.state[i][j];
		}
		for (int c = 0; c < Nb; c++) {
			state[0][c] = (byte) (multx((byte)0x02,tmp[0][c]) ^ (byte)multx((byte)0x03,tmp[1][c])
						  ^ tmp[2][c] ^ tmp[3][c]);
			state[1][c] = (byte) (tmp[0][c] ^ multx((byte) 0x02,tmp[1][c]) ^ multx((byte) 0x03,tmp[2][c]) ^ tmp[3][c]);
			state[2][c] = (byte) (tmp[0][c] ^ tmp[1][c] ^ multx((byte)0x02,tmp[2][c]) ^ multx((byte)0x03,tmp[3][c]));
			state[3][c] = (byte) (multx((byte)0x03,tmp[0][c]) ^ tmp[1][c] ^ tmp[2][c] ^ multx((byte)0x02,tmp[3][c]));
			                                 
			         
		}
	}
	
	private void addRoundKey (byte[][] words, int start) {
		for (int c = 0; c < Nb; c++) {
			state[0][c] ^= words[start+c][0];
			state[1][c] ^= words[start+c][1];
			state[2][c] ^= words[start+c][2];
			state[3][c] ^= words[start+c][3];
		}
	}
    
    private byte[] subWord (byte word[]) {
    	for(int i = 0; i < 4; i++) {
    		word[i] = SBox.sub(word[i]); // Is this correct?
    	} 
        return word;
    }
    
    private byte[] rotWord (byte word[]) {
        byte holder = word[0];
        
        for(int i = 0; i < 3; i++)
            word[i] = word[i+1];
        
        word[3] = holder;
        
        return word;
    }
    
    /* Inverse shift rows - first row not affected */
    private void invShiftRows() {
        byte tmp[][] = new byte[Nk][Nb];
        
        // Hard copy current state
		for (int i = 0; i < Nk; i++)
			for (int j = 0; j < Nb; j++)
				tmp[i][j] = this.state[i][j];
                
        // Shift rows
		for (int row = 1; row < Nb; row++)
            for (int col = 0; col < Nb; col++)
                this.state[row][(col+row)%Nb] = tmp[row][col];
	}
	
    
    private void keyExpansion () {
    	byte[] temp = new byte[4];

    	for (int i = 0; i < Nk; i++) {
    		w[i][0] = tkey[4*i];
    		w[i][1] = tkey[4*i+1];
    		w[i][2] = tkey[4*i+2];
    		w[i][3] = tkey[4*i+3];
    	}
    	
    	for(int i = Nk; i < (Nb * (Nr+1)); i++) {
    		for(int x = 0; x < 4; x++)
    			temp[x] = w[i-1][x];
    		if((i % Nk) == 0) {
    			temp = subWord(rotWord(temp));
    			temp[0] ^= rcon[i/Nk][0];
       		} else if((Nk > 6) && ((i % Nk) == 4)) 
    			temp = subWord(temp);
    		for(int x = 0; x < 4; x++)
                w[i][x] = (byte) (w[i-Nk][x] ^ temp[x]);
    	}
    }
	
	private void cipher () {		
		addRoundKey(w, 0);
		System.out.println("After Add Key");
		this.printstate();

		for (int round = 1; round < Nr; round++) {
			subBytes();
			System.out.println("After subBytes");
			this.printstate();

			shiftRows();
			System.out.println("After shiftRows");
			this.printstate();

			mixColumns();
			System.out.println("After mixColumns");
			this.printstate();

			addRoundKey(w, round*Nb);
			System.out.println("After Add Key");
			this.printstate();

		}
		subBytes();
		shiftRows();
		addRoundKey(w, Nr*Nb);
	}
	public byte[] encrypt (byte[] plaintxt) {
		this.state = new byte[Nk][Nb];
		for (int i = 0; i < Nk; i++) {
			for (int j = 0; j < Nb; j++)
				this.state[j][i] = plaintxt[4*i+j];
		}
		/*begin encryption here*/
		for (int i = 0; i < Nk; i++) {
			for (int j = 0; j < Nb; j++)
				plaintxt[4*i+j] = this.state[i][j];
		}
		cipher();
		return plaintxt;
	}
	public byte[] decrypt (byte[] ciphertxt) {
		return null;
	}
	public void printstate () {
		for (int i = 0; i < state.length; i++) {
			for (int j = 0; j < state[i].length; j++)
				System.out.printf("0x%02x, ", state[i][j]);
			System.out.println("");
		}
		System.out.println("");
	}
	public static void main (String[] args) {
		AES test = new AES(tkey);
		//0x57 * 0x13
		test.keyExpansion();
		for (int i = 0; i < test.w.length; i++) {
			System.out.print(i+":\t");
			for (int j = 0; j < test.w[i].length; j++)
				System.out.printf("0x%02x, ", test.w[i][j]);
			System.out.println("");
		}
		test.encrypt(tcipher);
		System.out.println("\nFinal State:");
		test.printstate();
	}
}
