FLAGS = -Wall -Wextra -Werror

SRCS = srcs/main.c srcs/net.c srcs/utils/utils.c srcs/Request/request_parser.c srcs/http_proxy.c
OBJS = $(SRCS:.c=.o)

NAME = ft_malcolm

all: $(NAME)

$(NAME): $(OBJS)
	@cc $(FLAGS) $(OBJS) -o $(NAME)

srcs/%.o: srcs/%.c srcs/ft_malcolm.h
	cc $(FLAGS) -c $< -o $@

clean:
	@rm -f $(OBJS)

fclean: clean
	@rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re