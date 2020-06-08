/*
This file contains code for mounting Persistent fault analysis attack on a des 
encryption scheme. 
For mounting the attack the plain text is encrypted twice-
1) Using functionally correct S-boxes
2) Using perturbed S-box at last round
Then the corresponding ciphertext are compared. The difference in correct ciphertext
and faulty ciphertext is used to discover the last round key value.
*/

#include "DES/des.cpp"

// File Exists or not utility function for I/O puposes........
int cfileexists(string filename){
    /* try to open file to read */
    FILE *file;
    if (file = fopen(filename.c_str(), "r")){
        fclose(file);
        return 1;
    }
    return 0;
}

void write_actual_last_rnd_keys(vector<int> actual_key[8])
{
	string filename = "IO_files/actualKey.txt";
	if (cfileexists(filename))
		return;

	ofstream myfile(filename);
	myfile << "Round 16 Actual Keys:\n\n";
	for (int i = 0; i < 8; i++)
	{
		myfile << "Sub-byte " << i << ": ";
		for (auto it : actual_key[i])
			myfile << it << " ";
		myfile << "\n\n";
	}
	myfile.close();
}
//---------------------------------------------------------

int main()
{
	freopen("IO_files/output.txt", "w", stdout); // Check outputs in this file..	

	char *plain_text = new char[3400];
	
	// Forming a random string......................
	// Readable ASCII Characters list[A-Z, a-z, 0-9, Symbols] 
	int lower = 32;
	int upper = 126;
	// Diversity of characters = 126-32+1 = 95
	// More is the diversity, more are the chances of attack (In Report).
	
	srand(time(0));
	int totalTrials = 100;
	int success = 0; // Value out of 100 trails................
	for(int tt=0;tt<totalTrials; tt++){
		Des d1, d2, d4;int i;
		for(i=0;i<3200;) // Using ~3200 as string length....
			plain_text[i++] = (char)((rand()%(upper-lower+1)) + lower);
		plain_text[i++]='\r',plain_text[i++]='\n';

		d1.Encrypt(plain_text, 0); // Without fault

		// cout<<"Input String :\n"<<str<<"\n";
		// cout<<"\nDecrypted plain text :\n"<< d2.Decrypt(str1)<< endl;
		
		d2.Encrypt(plain_text, 1); // With fault
		int totalPairs = CorrectL.size(); // Total pairs for comparison
		int xors[32];					// Xors of faulty and Correct R's
		int cnts[32];
		int S_Boxes[8];

		for(int i=0;i<32;i++)
			d4.sub[i] = i;			// Customising substitution values so that
													// inverseIP permutation could be found out..				

		d4.permutation();			// For inverseIP permutation
		d4.keygen();					// Actual keys for last Round generated.....

		vector<int> actual_key[8];

		for(int i=0;i<8;i++){
			for(int j=0;j<6;j++){
				actual_key[i].push_back(d4.keyi[15][6*i + j]); 
			}
		}
		write_actual_last_rnd_keys(actual_key);
		vector<int> predicted_keys[8]; // Storing predicted keys
											// for each of 8 sub-bits..

		for(int i=0; i < totalPairs; i++){

			for(int j=0;j<32;j++){

				xors[j] = CorrectR[i][j] ^ FaultyR[i][j];

				cnts[d4.p[j]] = xors[j];			// inverseIP permutation....

				d4.right[j] = CorrectL[i][j]; // Left Output is unchanged and equal
																			// to Prev Round R.
			}

			d4.Expansion();									// Left Output Expanded......

			for(int j=0;j<8;j++){						// Each of 8 sub-bits

				for(int k=0 ; k<=3 ; k++){

					if(cnts[4*j + k] && !predicted_keys[j].size()){ // Check if any of the 4 bits is 1.

						for(int ind = 0; ind<6; ind++)
							predicted_keys[j].push_back(d4.expansion[6*j + ind]);
						
						break;
					}
				}
			}
		}

		for(int i=0;i<8;i++){
			if(predicted_keys[i].size()){
				success++;

				cout<<"\nActual "<<i<<"th Sub-byte of last round's Key:\n";

				for(int j=0;j<6;j++){

					cout<<actual_key[i][j]<<" ";
				}

				cout << "\nPredicted " << i << "th Sub-byte of last round's Key:\n";

				for(auto it: predicted_keys[i]){
					cout<<it<<" ";
				}
				cout<<"\n\n";
			}
		}
	}

	cout<<"\n------------\nSuccess Rate: "<<success<<"/"<<totalTrials<<"\n";

	// cout<<"\n";
	// for(int i=0;i<32;i++)
	// 	cout<<CorrectR[0][i];

	// cout<<"\n";
	// for(int i=0;i<32;i++)
	// 	cout<<FaultyR[0][i];
	delete plain_text;
	return 0;
}
