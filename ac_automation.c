#include <stdio.h>
#include <string.h>
#include "ac_automation.h"

const int kind = 256;  //字母数量
const int MAX_SIZE = 500010; //节点最大数
const int KEYWORD_MAX_LEN = 55; //单词最大长度
const int INPUT_MAX_LEN = 1000010; //输入的字符串的最大长度

struct node
{
     node *fail;
     node *next[kind];
     int count;
     node()
     {
          fail = NULL;
          memset(next, 0, sizeof(next));
          count = 0;
     }
}*q[MAX_SIZE]; //该数组用于构建fail指针时的广搜队列


char keyword[KEYWORD_MAX_LEN];
char s[INPUT_MAX_LEN];
int head, tail;

void insert(char *s, node *root)
{
     node *p = root;
     int i = 0;
     while (s[i])
     {
          int index = (unsigned char)s[i];
          if (p->next[index] == NULL) p->next[index] = new node();
          p = p->next[index];
          i++;
     }
     p->count++;
}

void build_ac_automation(node *root)
{    
     head = tail = 0;
     root->fail = NULL;
     q[tail++] = root;
     while (head != tail)
     {
          node *tmp = q[head++];
          for (int i = 0; i < kind; i++)
          if (tmp->next[i] != NULL)
          {
               if (tmp == root) tmp->next[i]->fail = root;
               else
               {
                    node *p = tmp->fail;
                    while (p != NULL)
                    {
                         if (p->next[i] != NULL)
                         {
                              tmp->next[i]->fail = p->next[i];
                              break;
                         }
                         p = p->fail;
                    }
                    if (p == NULL)
                         tmp->next[i]->fail = root;
               }
               q[tail++] = tmp->next[i];
          }
     }
}

int query(char *s, node *root)
{
     node *p = root;
     //int ret = 0;
     int ret = -1;
     int i = 0;
     while (s[i])
     {
          int index = (unsigned char)s[i];
          while (p->next[index] == NULL && p != root) p = p->fail;
          p = p->next[index];
          if (p == NULL) p = root;
          if (p != root)
          {
               node *tmp = p;
               while (tmp != root && tmp->count != -1)
               {
				   return tmp->count;
                    //ret += tmp->count;
                    //tmp->count = -1;
                    //tmp = tmp->fail;
               }
          }
          i++;
     }
     return ret;
}

void destory(node *p)
{
	if (!p) return;
	for (int i = 0; i < kind; i++)
		destory(p->next[i]);
	delete p;
}


node *root;

void init_ac_automation(char *keys[], int size)
{
//	puts("init_ac_automation in");
	root = new node();
	for (int i = 0; i < size; i++)
		insert(keys[i], root);
	build_ac_automation(root);
//	puts("init_ac_automation out");
}

int query_string(char *s)
{
	return query(s, root);
}

void destroy_ac_automation()
{
	destory(root);
}
