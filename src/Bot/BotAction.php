<?php

namespace BadBehaviour\Bot;

enum BotAction: string
{
	case ALLOW      = 'allow';
	case CHALLENGE  = 'challenge';
	case BLOCK      = 'block';
	case LOG_ONLY   = 'log_only';
}
