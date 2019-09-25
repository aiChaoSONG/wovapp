#include <alsa/asoundlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <sys/stat.h>
#include <signal.h>
#include <ctype.h>


#define TLV_SIZE	4096
#define WRITE_SIZE	4000
#define READ_SIZE	3094
#define GHW_CFG_BLOB_SIG 0xc001515a // GHW_CFG_BLOB_SIG TLV TAG
#define GHW_CRC_VALUE 0x4B69AF6E
#define GHW_BLOG_FILE "en_us_data_memory.mmap"

/** \brief SOF ABI magic number "SOF\0". */
#define SOF_ABI_MAGIC		0x00464F53

/** \brief SOF ABI version major, minor and patch numbers */
#define SOF_ABI_MAJOR 3
#define SOF_ABI_MINOR 9
#define SOF_ABI_PATCH 0

/** \brief SOF ABI version number. Format within 32bit word is MMmmmppp */
#define SOF_ABI_MAJOR_SHIFT	24
#define SOF_ABI_MAJOR_MASK	0xff
#define SOF_ABI_MINOR_SHIFT	12
#define SOF_ABI_MINOR_MASK	0xfff
#define SOF_ABI_PATCH_SHIFT	0
#define SOF_ABI_PATCH_MASK	0xfff

#define SOF_ABI_VER(major, minor, patch) \
	(((major) << SOF_ABI_MAJOR_SHIFT) | \
	((minor) << SOF_ABI_MINOR_SHIFT) | \
	((patch) << SOF_ABI_PATCH_SHIFT))

#define SOF_ABI_VERSION_MAJOR(version) \
	(((version) >> SOF_ABI_MAJOR_SHIFT) & SOF_ABI_MAJOR_MASK)
#define SOF_ABI_VERSION_MINOR(version)	\
	(((version) >> SOF_ABI_MINOR_SHIFT) & SOF_ABI_MINOR_MASK)
#define SOF_ABI_VERSION_PATCH(version)	\
	(((version) >> SOF_ABI_PATCH_SHIFT) & SOF_ABI_PATCH_MASK)

#define SOF_ABI_VERSION_INCOMPATIBLE(sof_ver, client_ver)		\
	(SOF_ABI_VERSION_MAJOR((sof_ver)) !=				\
		SOF_ABI_VERSION_MAJOR((client_ver))			\
	)

#define SOF_ABI_VERSION SOF_ABI_VER(SOF_ABI_MAJOR, SOF_ABI_MINOR, SOF_ABI_PATCH)

#define BUFFER_TAG_OFFSET	0
#define BUFFER_SIZE_OFFSET	1
#define BUFFER_ABI_OFFSET	2

struct sof_abi_hdr {
	uint32_t magic;		/**< 'S', 'O', 'F', '\0' */
	uint32_t type;		/**< component specific type */
	uint32_t size;		/**< size in bytes of data excl. this struct */
	uint32_t abi;		/**< SOF ABI version */
	uint32_t reserved[4];	/**< reserved for future use */
	uint32_t data[0];	/**< Component data - opaque to core */
} __attribute__((packed));

enum sof_ipc_ctrl_cmd {
	SOF_CTRL_CMD_VOLUME = 0, /**< maps to ALSA volume style controls */
	SOF_CTRL_CMD_ENUM,	/**< maps to ALSA enum style controls */
	SOF_CTRL_CMD_SWITCH,	/**< maps to ALSA switch style controls */
	SOF_CTRL_CMD_BINARY,	/**< maps to ALSA binary style controls */
};


struct pcm_config {
	uint32_t channels;
	uint32_t rate;
	uint32_t period_count;
	snd_pcm_uframes_t period_size;
	snd_pcm_uframes_t buffer_size;
	snd_pcm_format_t format;
};
//static snd_pcm_uframes_t chunk_size = 0;
char errmsg[256];
static snd_pcm_t *capture_handle;
static FILE *captureFile;
static void err_exit(const char *err);
static void usage_exit(char **argv);
static snd_ctl_t *ctl_handle;
static snd_ctl_elem_info_t *ctl_info;
static snd_ctl_elem_id_t *ctl_id;
static snd_ctl_elem_value_t *ctl_value;
static char *ctl_name = "name=\"DETECT9.0 Hotword Model\"";
//static char *ctl_name_HWD = "name=\"hwd_in Switch\"";//Keyon: we might need add this switch to KPB for SOF, when disabled, kpb will always work on real-time mode.
//static char *turnOn = "1";
//static char *turnOff = "0"; // sof doesn't have this switch
static char *GHW_BLOG_file_path = NULL;
static char *device_name = NULL;
static int nonblock = 0;
static int open_mode = 0;
static int display_params = 0;
/* default config */
static struct pcm_config def_handle = {
	.channels = 2,
	.rate = 16000,
	.period_size = 2000,
	.period_count = 2000,
	.format = SND_PCM_FORMAT_S16_LE,
};

int set_mixer(char *idstr,const char *value);

static void err_exit( const char *err)
{
	//set_mixer(ctl_name_HWD, turnOff); 
	//sleep(1); 
	if (capture_handle)
		snd_pcm_close(capture_handle);
	if (captureFile)
		fclose(captureFile);
	fprintf(stderr, "Error (%s)\n", err);
	if (ctl_handle)
		snd_ctl_close(ctl_handle);
	exit(1);
}

static int ctl_is_bytes_tlv(void)
{
	if (!snd_ctl_elem_info_is_tlv_writable(ctl_info) ||
			(snd_ctl_elem_info_get_type(ctl_info) != SND_CTL_ELEM_TYPE_BYTES))
		return 0;
	return 1;
}

static void setup_mixer_ctl(char *idstr)
{
	int err;

	err = snd_ctl_ascii_elem_id_parse(ctl_id, idstr);
	if (err) {

		sprintf(errmsg, "Mixer parse id: %s", strerror(err));
		err_exit(errmsg);
	}

	snd_ctl_elem_info_set_id(ctl_info, ctl_id);

	err = snd_ctl_elem_info(ctl_handle, ctl_info);

	if (err) {
		sprintf(errmsg, "ctl info: %s", strerror(err));
		err_exit(errmsg);
	}

}

static void set_tlv_mixer()
{
	int err;
	unsigned int *tlv;
	static FILE *GHWBlobFilePtr;
	unsigned int GHWBlobFileSize=0;
	struct stat file_stats;
	struct sof_abi_hdr *hdr;

	if (!ctl_is_bytes_tlv()) {
		sprintf(errmsg, "set tlv: not a bytes tlv control");
		err_exit(errmsg);
	}

	GHWBlobFilePtr = fopen(GHW_BLOG_file_path,"rb");
	if(GHWBlobFilePtr == NULL) {
		sprintf(errmsg, "file open failed");
		err_exit(errmsg);
	}

	stat(GHW_BLOG_file_path, &file_stats);
	GHWBlobFileSize = file_stats.st_size;
	sprintf(errmsg, "set_tlv_mixer: ");

	printf("GHWBlobFileSize = %d\n", GHWBlobFileSize);
	tlv = calloc(1, GHWBlobFileSize + (2 * sizeof(unsigned int)) + sizeof(struct sof_abi_hdr));
//	tlv[0] = GHW_CFG_BLOB_SIG;
//	tlv[1] = GHWBlobFileSize; //param_obj_size
//	tlv[2] = GHW_CRC_VALUE;
	tlv[0] = SOF_CTRL_CMD_BINARY; //SOF_CTRL_CMD_BINARY, 3
	tlv[1] = GHWBlobFileSize + sizeof(struct sof_abi_hdr); //param_obj_size

	hdr = (struct sof_abi_hdr*)&tlv[2];
	hdr->magic = SOF_ABI_MAGIC;
	hdr->type = 1;//set model
	hdr->abi = SOF_ABI_VERSION;
	char *GHWBlobAddr = (char *)&tlv[2] + sizeof(struct sof_abi_hdr);
	size_t count = fread(GHWBlobAddr, GHWBlobFileSize, 1, GHWBlobFilePtr);
	if (count != 1) {
		sprintf(errmsg, "GHWBlobFile Read Error!");
		err_exit(errmsg);
	}   

	err = snd_ctl_elem_tlv_write(ctl_handle, ctl_id, tlv);
	if (err < 0) {
		sprintf(errmsg, "ctl tlv write: %s", strerror(err));
		err_exit(errmsg);
	}
}

int set_wov_algo_params()
{
	int err = 0;

	err = snd_ctl_open(&ctl_handle, "hw:0", 0);
	if (err) {
		sprintf(errmsg, "control open: %s", strerror(err));
		err_exit(errmsg);
	}

	snd_ctl_elem_info_alloca(&ctl_info);
	snd_ctl_elem_id_alloca(&ctl_id);
	snd_ctl_elem_value_alloca(&ctl_value);

	setup_mixer_ctl(ctl_name);
	set_tlv_mixer();

	return 0;
}

char * strtrim(char *str)
{
	char *end,*sp,*ep;
	int len;
	sp = str;
	end = str + strlen(str) - 1;
	ep = end;
 
	while(sp<=end && isspace(*sp))
		sp++;
	while(ep>=sp && isspace(*ep))
		ep--;
	len = (ep < sp) ? 0:(ep-sp)+1;
	sp[len] = '\0';
	return sp;
}

int set_mixer(char *idstr, const char *value)
{
	int err = 0;
	static snd_ctl_t *ctl_handle_mixer;
	static snd_ctl_elem_info_t *ctl_info_mixer;
	static snd_ctl_elem_id_t *ctl_id_mixer;
	static snd_ctl_elem_value_t *ctl_value_mixer;

	err = snd_ctl_open(&ctl_handle_mixer, "hw:0", 0); //arg[1]= device name
	if (err) {
		sprintf(errmsg, "control open: %s", strerror(err));
		err_exit(errmsg);
	}

	snd_ctl_elem_info_alloca(&ctl_info_mixer);
	snd_ctl_elem_id_alloca(&ctl_id_mixer);
	snd_ctl_elem_value_alloca(&ctl_value_mixer);

	err = snd_ctl_ascii_elem_id_parse(ctl_id_mixer, idstr);
	if (err) {

		sprintf(errmsg, "Mixer parse id: %s", strerror(err));
		err_exit(errmsg);
	}

	snd_ctl_elem_info_set_id(ctl_info_mixer, ctl_id_mixer);

	err = snd_ctl_elem_info(ctl_handle_mixer, ctl_info_mixer);

	if (err) {
		sprintf(errmsg, "ctl info: %s", strerror(err));
		err_exit(errmsg);
	}

	snd_ctl_elem_info_get_id(ctl_info_mixer, ctl_id_mixer);
	snd_ctl_elem_value_set_id(ctl_value_mixer, ctl_id_mixer);
	if ((err = snd_ctl_elem_read(ctl_handle_mixer, ctl_value_mixer)) < 0) {
		sprintf(errmsg, "Cannot read the given element from control %s\n", strerror(err));
		err_exit(errmsg);
	}
	err = snd_ctl_ascii_value_parse(ctl_handle_mixer, ctl_value_mixer, ctl_info_mixer,value );
	if (err < 0) {
		sprintf(errmsg,"Control parse error: %s\n", strerror(err));
		err_exit(errmsg);
	}
	if ((err = snd_ctl_elem_write(ctl_handle_mixer, ctl_value_mixer)) < 0) {
		sprintf(errmsg,"Control write error: %s\n", strerror(err));
		err_exit(errmsg);
	}
	return 0;
}



void usage_exit( char *argv[])
{
	fprintf(stderr, "Usage: %s -Dhw:cardnum,devicenum [option]... [FILE]... \n", argv[0]);
	fprintf(stderr, "-D specify capture device\n"
	        "-d capture duration in seconeds\n"
			"-f specify format, default s16_le\n"
		    "-p specify period size\n"
			"-c specify period count\n"
			"-b specify blob file path\n"
			"-t set wov algo params\n"
			"-N use nonblock mode\n"
			"-s show hardware parameters\n"
			"-h show help infomation\n");
	exit(EXIT_FAILURE);
}

void sighandler(int signum)
{
	sprintf(errmsg,"Caught signal %d, program now exit", signum);
	err_exit(errmsg);
}

void show_params(snd_pcm_t *handle, snd_pcm_hw_params_t *params) {
	
	unsigned int val, val2;
	int dir;
	snd_pcm_uframes_t frames;

	printf("--------------HW Parameters---------------\n");

	printf("PCM handle name = '%s'\n", snd_pcm_name(handle));
	printf("PCM state = %s\n", snd_pcm_state_name(snd_pcm_state(handle)));

	snd_pcm_hw_params_get_access(params, (snd_pcm_access_t *) &val);
  	printf("access type = %s\n", snd_pcm_access_name((snd_pcm_access_t)val));

	snd_pcm_hw_params_get_format(params, (snd_pcm_format_t*)&val);
  	printf("format = '%s' (%s)\n", snd_pcm_format_name((snd_pcm_format_t)val),
    snd_pcm_format_description((snd_pcm_format_t)val));

	snd_pcm_hw_params_get_subformat(params, (snd_pcm_subformat_t *)&val);
  	printf("subformat = '%s' (%s)\n", snd_pcm_subformat_name((snd_pcm_subformat_t)val),
    snd_pcm_subformat_description((snd_pcm_subformat_t)val));

	snd_pcm_hw_params_get_channels(params, &val);
  	printf("channels = %d\n", val);

	snd_pcm_hw_params_get_rate(params, &val, &dir);
  	printf("rate = %d\n", val);

	snd_pcm_hw_params_get_rate_numden(params, &val, &val2);
  	printf("exact rate = %d/%d\n", val, val2);

	snd_pcm_hw_params_get_period_time(params, &val, &dir);
  	printf("period time = %d us\n", val);
	
	snd_pcm_hw_params_get_period_size(params, &frames, &dir);
  	printf("period size = %d frames\n", (int)frames);

	snd_pcm_hw_params_get_buffer_time(params, &val, &dir);
  	printf("buffer time = %d us\n", val);

	snd_pcm_hw_params_get_buffer_size(params, &frames);
  	printf("buffer size = %ld frames\n", frames);
	
	snd_pcm_hw_params_get_periods(params, &val, &dir);
  	printf("periods per buffer = %d frames\n", val);

	val = snd_pcm_hw_params_get_sbits(params);
  	printf("significant bits = %d\n", val);

	val = snd_pcm_hw_params_is_batch(params);
  	printf("is batch = %s\n", val ? "Yes" : "No");

  	val = snd_pcm_hw_params_can_pause(params);
  	printf("can pause = %d\n", val);

	val = snd_pcm_hw_params_can_resume(params);
  	printf("can resume = %d\n", val);

	printf("-----------End of HW Parameters-----------\n");
}

int main (int argc, char *argv[])
{
	int i;
	int err;
    unsigned char *bufptr; 
	snd_pcm_hw_params_t *hw_params;
    int size = 0;
	int num_write;
	int opt;
    int d_flag = 0;
    int p_flag = 0;
    int c_flag = 0;
    int default_user_duration = 10;
    uint32_t user_duration = default_user_duration;
    uint32_t user_periodSize = 0;
    uint32_t user_periodCount = 0;
    uint32_t duration_in_bytes = 0;
	//snd_pcm_status_t *status;

	signal(SIGINT, sighandler);
	if ( argc == 1 )
		usage_exit(argv);

	GHW_BLOG_file_path = (char*)malloc(500* sizeof(char));
	strcpy(GHW_BLOG_file_path, GHW_BLOG_FILE);

	while ((opt = getopt(argc, argv, "D:d:hp:c:b:tNsf:")) != -1) {
		switch (opt) {
			case 'd':
				d_flag = 1;
				user_duration = atol(optarg);
				duration_in_bytes=def_handle.rate *def_handle.channels*user_duration *2;
				printf("flag %c is set with value %d \n",opt,user_duration);
				break;
			case 'p':
				p_flag = 1;
				user_periodSize = atol(optarg);
				def_handle.period_size=user_periodSize;
				printf("flag %c is set with value %d \n",opt,user_periodSize);
				break;
			case 'c':
				c_flag = 1;
				user_periodCount = atol(optarg);
				def_handle.period_count=user_periodCount;
				printf("flag %c is set with value %d \n",opt,user_periodCount);
				break;
			case 'b':
				if (strlen(optarg)<=500)
					strcpy(GHW_BLOG_file_path,optarg);

				printf("flag %c is set with value %s \n", opt, GHW_BLOG_file_path);
				break;

			case 'D':
				device_name=optarg;
				printf("flag %c is set with value %s \n",opt,device_name);
				break;

			case 't':
				set_wov_algo_params();
				sleep(2);
				printf("Setting Wov Algo params is completed\n");
				break;

			case 'N':
				nonblock = 1;
				open_mode |= SND_PCM_NONBLOCK;
				break;

			case 's':
				display_params = 1;
				break;

			case 'f':
				def_handle.format = snd_pcm_format_value(strtrim(optarg));
				if(def_handle.format == SND_PCM_FORMAT_UNKNOWN) 
					err_exit("Format not recognized");
				break;

			case 'h':
			default:
				usage_exit(argv);
		}
	}	

    if ( ! (d_flag || p_flag || c_flag)) {
		printf("no flag ( -d or -p or -c )  are selected, so continuing with default values\n");
	}

	captureFile = fopen("capture.pcm", "wb");
	if (!captureFile)
		err_exit("unable to open file to record");

	if ((err = snd_pcm_open(&capture_handle, device_name, SND_PCM_STREAM_CAPTURE, open_mode)) < 0) {
		fprintf(stderr, "cannot open audio device %s (%s)\n", argv[1], snd_strerror (err));
		err_exit(strerror(err));
	}
	   
	if ((err = snd_pcm_hw_params_malloc(&hw_params)) < 0) {
		fprintf(stderr, "cannot allocate hardware parameter structure (%s)\n", snd_strerror (err));
		err_exit(strerror(err));
	}
			 
	if ((err = snd_pcm_hw_params_any(capture_handle, hw_params)) < 0) {
		fprintf(stderr, "cannot initialize hardware parameter structure (%s)\n", snd_strerror (err));
		err_exit(strerror(err));
	}
	
	if ((err = snd_pcm_hw_params_set_access(capture_handle, hw_params, SND_PCM_ACCESS_MMAP_INTERLEAVED)) < 0) {
		fprintf(stderr, "cannot set access type (%s)\n", snd_strerror (err));
		err_exit(strerror(err));
	}
	
	if ((err = snd_pcm_hw_params_set_format(capture_handle, hw_params, def_handle.format)) < 0) {
		fprintf(stderr, "cannot set sample format (%s)\n", snd_strerror (err));
		err_exit(strerror(err));
	}
	
	if ((err = snd_pcm_hw_params_set_rate_near(capture_handle, hw_params, &def_handle.rate, 0)) < 0) {
		fprintf(stderr, "cannot set sample rate (%s)\n", snd_strerror (err));
		err_exit(strerror(err));
	}
	
	if ((err = snd_pcm_hw_params_set_channels(capture_handle, hw_params, def_handle.channels)) < 0) {
		fprintf(stderr, "cannot set channel count (%s)\n", snd_strerror (err));
		err_exit(strerror(err));
	}
	
    if((err = snd_pcm_hw_params_set_period_size_near(capture_handle, hw_params, &def_handle.period_size, 0)) < 0)
	        err_exit(strerror(err));
		
	if((err = snd_pcm_hw_params_set_periods_near(capture_handle, hw_params, &def_handle.period_count, 0)) < 0)
	        err_exit(strerror(err));

	def_handle.buffer_size = def_handle.period_size * def_handle.period_count;

	if((err = snd_pcm_hw_params_set_buffer_size_near(capture_handle, hw_params, &def_handle.buffer_size))<0)
		err_exit(strerror(err));

	if ((err = snd_pcm_hw_params(capture_handle, hw_params)) < 0) {
		fprintf(stderr, "cannot set parameters (%s)\n", snd_strerror (err));
		err_exit(strerror(err));
	}

	if ((err = snd_pcm_prepare (capture_handle)) < 0) {
		fprintf(stderr, "cannot prepare audio interface for use (%s)\n", snd_strerror (err));
		err_exit(strerror(err));
	}

	if ((err = snd_pcm_start (capture_handle)) < 0) {
                fprintf(stderr, "cannot start audio interface for use (%s)\n", snd_strerror (err));
		err_exit(strerror(err));
	}
	       
	size = snd_pcm_frames_to_bytes(capture_handle, def_handle.period_size);
	//fprintf(stderr, "def_handle.period_size %d, size %u\n",(int) def_handle.period_size, size);				 

	bufptr = (unsigned char *)malloc(size);

//	set_mixer(ctl_name_HWD, turnOn);

	if (display_params)
		show_params(capture_handle, hw_params);

	printf("Waiting to be triggered\n");
read1:
	err = snd_pcm_mmap_readi(capture_handle, bufptr, def_handle.period_size);
	if (err == -EAGAIN) {
		snd_pcm_wait(capture_handle, 100);
		goto read1;
	}

	if (err == -ESTRPIPE) {
		fprintf(stderr, "stream suspended, resuming stream\n");
		while (snd_pcm_resume(capture_handle))
			sleep(1);   /* wait until suspend flag is released */
		fprintf(stderr, "stream suspended, resuming stream\n");
	}

	snd_pcm_uframes_t should_read;
	unsigned char *buf;

	for (i = 0; i < (int)ceil(duration_in_bytes/(size*1.0)); ++i) {
read2:
		if (nonblock) {
			should_read = def_handle.period_size;
			buf = bufptr;
			while(should_read > 0) {
				err = snd_pcm_mmap_readi (capture_handle, buf, should_read);
				if (err == -EAGAIN || (err >= 0 && (size_t)err < should_read)) {
					snd_pcm_wait(capture_handle, 100);
				} else if(err < 0) {
					err_exit("read error");
				}

				if (err > 0) {
					should_read -= err;
					buf += snd_pcm_frames_to_bytes(capture_handle, err);
				}
			}
			fprintf(stderr, "%d - read from audio interface\n", i+1);
		} else {
			if ((err = snd_pcm_mmap_readi (capture_handle, bufptr, def_handle.period_size)) != def_handle.period_size) {
				if (err == -EAGAIN) {
					snd_pcm_wait(capture_handle, 100);
					goto read2;
				}

				fprintf(stderr, "read from audio interface failed (%s): %d\n", snd_strerror (err), err);
				continue;
			}
			fprintf(stderr, "%d - read from audio interface  (%d)\n", i+1,err);
		}

		num_write = fwrite(bufptr, 1, size, captureFile);

		if(num_write<size)
			fprintf(stderr, "required bytes %d, available bytes%d\n", size, num_write);				 
	}

    fprintf (stderr, "number of iterations should be : %d based on given duration and period size\n",(int)ceil(duration_in_bytes/(size*1.0)));

//	set_mixer(ctl_name_HWD, turnOff);

	snd_pcm_hw_params_free(hw_params);
	snd_pcm_close(capture_handle);

    free(bufptr);
    printf("Recording completed\n");
	exit (0);
}

