FLAGS = -Wall -Wextra -Werror

SRCS = main.c net.c utils/parse_addr.c Request/request_parser.c http_proxy.c
OBJS = $(SRCS:.c=.o)
NAME = ft_malcom

all: $(NAME)

$(NAME): $(OBJS) ####################### relink
	@cc $(FLAGS) $(OBJS) -o $(NAME)

clean:
	@rm -f $(OBJS)

fclean: clean
	@rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re