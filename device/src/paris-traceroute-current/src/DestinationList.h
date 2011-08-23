class DestinationList {
	private:
		FILE *f;
		char* dest;
	public:
		DestinationList ();
		void setFile (char *f);
		void setAddr (char *addr);
		bool next(char *addr); 
};
